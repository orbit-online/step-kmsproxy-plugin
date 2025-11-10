package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/elazarl/goproxy"
	"github.com/orbit-online/step-kmsproxy-plugin/listeners"
	stepCLI "github.com/smallstep/cli-utils/step"
	stepKey "go.step.sm/crypto/keyutil"
	stepKMS "go.step.sm/crypto/kms"
	stepKMSAPI "go.step.sm/crypto/kms/apiv1"
	stepX509 "go.step.sm/crypto/x509util"

	// KMS modules (https://github.com/smallstep/step-kms-plugin/blob/3be48fd238cdc1d40dfad5e6410cf852544c3b4f/main.go#L19-L29)
	_ "go.step.sm/crypto/kms/awskms"
	_ "go.step.sm/crypto/kms/azurekms"
	_ "go.step.sm/crypto/kms/capi"
	_ "go.step.sm/crypto/kms/cloudkms"
	_ "go.step.sm/crypto/kms/mackms"
	_ "go.step.sm/crypto/kms/pkcs11"
	_ "go.step.sm/crypto/kms/softkms"
	_ "go.step.sm/crypto/kms/sshagentkms"
	_ "go.step.sm/crypto/kms/tpmkms"
	_ "go.step.sm/crypto/kms/yubikey"
)

type Params struct {
	ClientKey          string   `required:"" arg:"" name:"clientkey" help:"Filesystem path or Smallstep KMS key URI to use for mTLS connections"`
	CAKey              string   `required:"" arg:"" name:"cakey" help:"Filesystem path or Smallstep KMS key URI used for creating certificates trusted by proxy clients"`
	ClientCert         *string  `name:"clientcert" help:"Path to client certificate matching the key at <clientkey> (defaults to using <clientkey>)"`
	CACert             *string  `name:"cacert" help:"Path to CA certificate matching the key at <cakey> (defaults to using <cakey>)"`
	Trust              []string `name:"trust" help:"CA bundle to trust beyond the system trust store, can be specified multiple times." type:"path"`
	Listen             string   `help:"Listening address (unix:<PATH>, tcp:<HOSTNAME>:<PORT>, or systemd:)" default:"tcp:localhost:8090"`
	PACPort            int      `help:"Localhost port for serving AutoProxyConfiguration.js" type:"int" default:"8091"`
	PAC                *string  `help:"Path to AutoProxyConfiguration.js" type:"path"`
	InsecureSkipVerify bool     `help:"Disable validation of server certificates"`
	Verbose            bool     `help:"Turn on verbose logging"`
}

var params Params

func main() {
	kong.Parse(&params, kong.Name("step-kmsproxy-plugin"), kong.Description("Use smallstep to create mTLS tunnels"))
	err := startProxy(context.Background(), params)
	if err != nil {
		log.Fatal(err)
	}
}

func startProxy(ctx context.Context, params Params) error {
	caCert, err := loadKeyCert(ctx, params.CAKey, params.CACert)
	if err != nil {
		return err
	}

	if params.PAC != nil {
		localhostCert, err := signCertificateForHost(caCert, "localhost")
		if err != nil {
			return err
		}
		pacListener, err := tls.Listen("tcp", fmt.Sprintf("localhost:%d", params.PACPort), &tls.Config{
			Certificates: []tls.Certificate{*localhostCert},
		})
		if err != nil {
			return err
		}
		pacServer := http.Server{
			Handler: http.HandlerFunc(func(writer http.ResponseWriter, reader *http.Request) {
				http.ServeFile(writer, reader, *params.PAC)
			}),
		}
		go pacServer.Serve(pacListener)
	}

	proxyProto, proxyAddr, found := strings.Cut(params.Listen, ":")
	if !found {
		return fmt.Errorf("unable to determine listening method in --listen option, expected <PROTO>:<ADDR>, got %s", params.Listen)
	}
	proxyListener, err := listeners.CreateListener(proxyProto, proxyAddr)
	if err != nil {
		return err
	}
	proxy, err := createProxy(ctx, params.ClientKey, params.ClientCert, caCert, params.Trust, params.InsecureSkipVerify, params.Verbose)
	if err != nil {
		return err
	}

	go proxy.Serve(proxyListener)

	fmt.Println("Startup completed")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	return err
}

func createProxy(
	ctx context.Context,
	kmsUri string,
	clientCertPath *string,
	caCert *tls.Certificate,
	caBundlePaths []string,
	insecureSkipVerify bool,
	verbose bool,
) (*http.Server, error) {
	trustPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("unable to load system certificates: %w", err)
	}
	for _, caBundlePath := range caBundlePaths {
		rawBundle, err := os.ReadFile(caBundlePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA bundle at %s: %w", caBundlePath, err)
		}
		ok := trustPool.AppendCertsFromPEM(rawBundle)
		if !ok {
			return nil, fmt.Errorf("failed to append %s to the certificate store", caBundlePath)
		}
	}

	// Test loading
	_, err = loadKeyCert(ctx, kmsUri, clientCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = verbose
	proxy.AllowHTTP2 = true
	mitmAction := &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(caCert)}
	var mitmHandler goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return mitmAction, host
	}
	proxy.OnRequest().HandleConnect(mitmHandler)
	proxy.OnRequest().DoFunc(func(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		proxyCtx.Proxy.Tr.TLSClientConfig = &tls.Config{
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return loadKeyCert(ctx, kmsUri, clientCertPath)
			},
			Renegotiation:      tls.RenegotiateFreelyAsClient,
			RootCAs:            trustPool,
			InsecureSkipVerify: insecureSkipVerify,
		}
		return req, nil
	})

	return &http.Server{Handler: http.HandlerFunc(proxy.ServeHTTP)}, nil
}

// Only used for the localhost PAC server signing, the proxy lib has its own function that is not exposed
func signCertificateForHost(caCert *tls.Certificate, host string) (*tls.Certificate, error) {
	key, err := stepKey.GenerateDefaultSigner()
	if err != nil {
		return nil, err
	}
	csr, err := stepX509.CreateCertificateRequest(host, []string{host}, key)
	if err != nil {
		return nil, err
	}
	tpl, err := stepX509.CreateCertificateTemplate(csr)
	if err != nil {
		return nil, err
	}
	tpl.NotBefore = time.Now().Add(-time.Hour * 1)
	tpl.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	cert, err := stepX509.CreateCertificate(tpl, caCert.Leaf, tpl.PublicKey, caCert.PrivateKey.(crypto.Signer))
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}, nil
}

func loadKeyCert(ctx context.Context, kuri string, certPath *string) (*tls.Certificate, error) {
	km, err := openKMS(ctx, kuri)
	if err != nil {
		return nil, fmt.Errorf("unable to open KMS using URI %s: %w", kuri, err)
	}
	cm, ok := km.(stepKMSAPI.CertificateChainManager)
	if !ok {
		return nil, fmt.Errorf("unable to load certificates from KMS: %s", km)
	}
	var rawCerts [][]byte
	if certPath == nil {
		cert, err := cm.LoadCertificateChain(&stepKMSAPI.LoadCertificateChainRequest{
			Name: kuri,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to load certificates from KMS URI %s: %w", kuri, err)
		}
		for _, c := range cert {
			rawCerts = append(rawCerts, c.Raw)
		}
	} else {
		rawBundle, err := os.ReadFile(*certPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read client cert at %s: %w", *certPath, err)
		}
		// https://gist.github.com/laher/5795578
		var cert tls.Certificate
		var certPart *pem.Block
		for {
			certPart, rawBundle = pem.Decode(rawBundle)
			if certPart == nil {
				break
			}
			if certPart.Type == "CERTIFICATE" {
				cert.Certificate = append(cert.Certificate, certPart.Bytes)
			}
		}
		rawCerts = cert.Certificate
	}
	key, err := km.CreateSigner(&stepKMSAPI.CreateSignerRequest{
		SigningKey: kuri,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load private key using KMS URI %s: %w", kuri, err)
	}
	keyCert := &tls.Certificate{
		Certificate: rawCerts,
		PrivateKey:  key,
	}
	if keyCert.Leaf, err = x509.ParseCertificate(keyCert.Certificate[0]); err != nil {
		return nil, fmt.Errorf("failed to parse certificate leaf in %s: %w", *certPath, err)
	}
	return keyCert, nil
}

// Source: https://github.com/smallstep/step-kms-plugin/blob/3be48fd238cdc1d40dfad5e6410cf852544c3b4f/cmd/root.go#L74-L94
func openKMS(ctx context.Context, kuri string) (stepKMSAPI.KeyManager, error) {
	typ, err := stepKMSAPI.TypeOf(kuri)
	if err != nil {
		return nil, err
	}

	var storageDirectory string
	if typ == stepKMSAPI.TPMKMS {
		if err := stepCLI.Init(); err != nil {
			return nil, err
		}
		storageDirectory = filepath.Join(stepCLI.Path(), "tpm")
	}

	// Type is not necessary, but it avoids an extra validation
	return stepKMS.New(ctx, stepKMSAPI.Options{
		Type:             typ,
		URI:              kuri,
		StorageDirectory: storageDirectory,
	})
}
