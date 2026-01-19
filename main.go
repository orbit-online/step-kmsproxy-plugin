package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/fsnotify/fsnotify"
	"github.com/orbit-online/step-kmsproxy-plugin/listeners"
	stepCLI "github.com/smallstep/cli-utils/step"
	stepKey "go.step.sm/crypto/keyutil"
	stepKMS "go.step.sm/crypto/kms"
	stepKMSAPI "go.step.sm/crypto/kms/apiv1"
	stepX509 "go.step.sm/crypto/x509util"
	"golang.org/x/sync/errgroup"

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
	Listen             string   `help:"Cleartext listening address (unix:<PATH>, tcp:<HOSTNAME>:<PORT>, or systemd:)" default:"tcp:localhost:8090"`
	ListenTLS          string   `help:"TLS listening address (unix:<PATH>, tcp:<HOSTNAME>:<PORT>, or systemd:)" default:"tcp:localhost:8091"`
	PACPort            int      `help:"Localhost port for serving AutoProxyConfiguration.js" type:"int" default:"8092"`
	PAC                *string  `help:"Path to AutoProxyConfiguration.js" type:"path"`
	InsecureSkipVerify bool     `help:"Disable validation of server certificates"`
	Verbose            bool     `help:"Turn on verbose logging"`
}

var params Params

func main() {
	kong.Parse(&params, kong.Name("step-kmsproxy-plugin"), kong.Description("Use smallstep to create mTLS tunnels"))
	slog.SetDefault(slog.Default())
	if params.Verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	err := startProxy(context.Background(), params)
	if err != nil {
		log.Fatal(err)
	}
}

func startProxy(ctx context.Context, params Params) error {
	var wg errgroup.Group
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)
	caCert, err := loadKeyCert(ctx, params.CAKey, params.CACert)
	if err != nil {
		return err
	}

	if params.PAC != nil {
		wg.Go(func() error { return createPACServer(caCert) })
	}

	handleRequest, err := createProxyHandler(ctx, params.ClientKey, params.ClientCert, caCert, params.Trust, params.InsecureSkipVerify, sigs)
	if err != nil {
		return err
	}

	if params.ClientCert != nil {
		wg.Go(func() error { return watchClientCertificate(*params.ClientCert, sigs) })
	}

	wg.Go(func() error {
		proxyProtoCleartext, proxyAddrCleartext, found := strings.Cut(params.Listen, ":")
		if !found {
			return fmt.Errorf("unable to determine listening method in --listen option, expected <PROTO>:<ADDR>, got %s", params.Listen)
		}
		proxyListenerCleartext, err := listeners.CreateListener(proxyProtoCleartext, proxyAddrCleartext)
		if err != nil {
			return err
		}
		for {
			conn, err := proxyListenerCleartext.Accept()
			if err != nil {
				return err
			}
			go handleRequest(conn, false)
		}
	})

	wg.Go(func() error {
		proxyCert, err := signCertificate(caCert, "localhost", []string{"localhost", "127.0.0.1"})
		if err != nil {
			return err
		}
		proxyTLSConfig := &tls.Config{
			Certificates:       []tls.Certificate{*proxyCert},
			ClientSessionCache: tls.NewLRUClientSessionCache(-1),
			MinVersion:         tls.VersionTLS12,
		}
		proxyProtoTLS, proxyAddrTLS, found := strings.Cut(params.ListenTLS, ":")
		if !found {
			return fmt.Errorf("unable to determine listening method in --listen-tls option, expected <PROTO>:<ADDR>, got %s", params.Listen)
		}
		proxyListenerTLS, err := listeners.CreateListener(proxyProtoTLS, proxyAddrTLS)
		if err != nil {
			return err
		}
		for {
			conn, err := proxyListenerTLS.Accept()
			if err != nil {
				return err
			}
			go func(rawClientConn net.Conn) {
				defer rawClientConn.Close()
				handleRequest(tls.Server(rawClientConn, proxyTLSConfig), true)
			}(conn)
		}
	})

	slog.Info("Startup completed")

	if err := wg.Wait(); err != nil {
		return err
	}
	return nil
}

func createPACServer(caCert *tls.Certificate) error {
	localhostCert, err := signCertificate(caCert, "localhost", []string{"localhost", "127.0.0.1"})
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
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			http.ServeFile(writer, req, *params.PAC)
		}),
	}
	return pacServer.Serve(pacListener)
}

func watchClientCertificate(clientCertPath string, sigs chan os.Signal) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create filesystem watcher to reload client certificate: %w", err)
	}
	defer watcher.Close()
	err = watcher.Add(clientCertPath)
	if err != nil {
		return fmt.Errorf("failed to watch client certificate path %s: %w", clientCertPath, err)
	}

	slog.Info("Monitoring changes to client certificate", "clientCertPath", clientCertPath)
	for {
		select {
		case _, ok := <-watcher.Events:
			if !ok {
				return fmt.Errorf("Watcher was closed")
			}
			slog.Info("Client certificate changed", "clientCertPath", clientCertPath)
			sigs <- syscall.SIGHUP
		case err, ok := <-watcher.Errors:
			if !ok {
				return fmt.Errorf("Watcher was closed")
			}
			slog.Warn("Error while watching client certificate", "err", err)
		}
	}
}

func createProxyHandler(
	ctx context.Context,
	kmsUri string,
	clientCertPath *string,
	caCert *tls.Certificate,
	caBundlePaths []string,
	insecureSkipVerify bool,
	sigs chan os.Signal,
) (func(clientConn net.Conn, isTLS bool), error) {
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

	var cachedCert *tls.Certificate
	loadCachedKeyCert := func() (*tls.Certificate, error) {
		select {
		case sig := <-sigs:
			if sig == syscall.SIGHUP {
				slog.Debug("Reload signal received, invalidating cached client certificate")
				cachedCert = nil
			}
		default:
		}
		if cachedCert != nil && cachedCert.Leaf.NotAfter.Add(-time.Minute*1).Compare(time.Now()) < 1 {
			slog.Debug("Client certificate expires in less than a minute, invalidating cache")
			cachedCert = nil
		}
		if cachedCert == nil {
			cachedCert, err = loadKeyCert(ctx, kmsUri, clientCertPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}
		}
		return cachedCert, nil
	}

	// Test loading
	_, err = loadCachedKeyCert()
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	cachedProxyCerts := map[string]*tls.Certificate{}
	getServerTLSConfig := func(commonName string, sans []string) *tls.Config {
		config := tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				var cert *tls.Certificate
				var ok bool
				if cert, ok = cachedProxyCerts[hello.ServerName]; !ok {
					cert, err = signCertificate(caCert, commonName, sans)
					if err != nil {
						return nil, err
					}
					cachedProxyCerts[commonName] = cert
					for _, san := range sans {
						cachedProxyCerts[san] = cert
					}
				}
				return cert, nil
			},
			ClientSessionCache: tls.NewLRUClientSessionCache(-1),
			MinVersion:         tls.VersionTLS12,
		}
		return &config
	}

	successResponse := http.Response{StatusCode: 200, Status: "Connection Established", ProtoMajor: 1, ProtoMinor: 1}
	errorResponse := http.Response{StatusCode: 502, Status: "Connection Failed", ProtoMajor: 1, ProtoMinor: 1}

	remoteTLSConfig := tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return loadCachedKeyCert()
		},
		Renegotiation:      tls.RenegotiateFreelyAsClient,
		RootCAs:            trustPool,
		InsecureSkipVerify: insecureSkipVerify,
		ClientSessionCache: tls.NewLRUClientSessionCache(-1),
	}

	handleRequest := func(rawClientConn net.Conn, clientIsTLS bool) {
		defer rawClientConn.Close()
		if clientIsTLS {
			slog.Debug("New TLS request", "client", rawClientConn.RemoteAddr())
		} else {
			slog.Debug("New cleartext request", "client", rawClientConn.RemoteAddr())
		}
		reqBuf := bytes.NewBuffer(nil)
		req, err := http.ReadRequest(bufio.NewReader(io.TeeReader(rawClientConn, reqBuf)))
		if err != nil {
			slog.Error("Error parsing HTTP request", "req", req, "err", err)
			return
		}
		var remoteAddr string
		if req.Method == http.MethodConnect {
			remoteAddr = req.Host
		} else {
			if matched, err := regexp.Match(`^[^:]+:[0-9]+$`, []byte(req.Host)); !matched || err != nil {
				if clientIsTLS {
					remoteAddr = req.Host + ":443"
				} else {
					remoteAddr = req.Host + ":80"
				}
			} else {
				remoteAddr = req.Host
			}
		}
		var remoteConn net.Conn
		var clientConn net.Conn
		if clientIsTLS {
			slog.Debug("Establishing TLS connection", "remote", remoteAddr)
			remoteTLSConn, err := tls.Dial("tcp", remoteAddr, &remoteTLSConfig)
			if err != nil {
				slog.Error("Failed to establish connection", "remote", remoteAddr)
				if req.Method == http.MethodConnect {
					errorResponse.Write(rawClientConn)
				}
				return
			}
			defer remoteTLSConn.Close()
			slog.Debug("Connected to remote", "remote", remoteAddr)
			if len(remoteTLSConn.ConnectionState().PeerCertificates) == 0 {
				slog.Error("No peer certificate received from remote", "remote", remoteAddr)
				return
			}
			remotePeerCert := remoteTLSConn.ConnectionState().PeerCertificates[0]
			remoteSans := []string{}
			for _, addr := range remotePeerCert.DNSNames {
				remoteSans = append(remoteSans, addr)
			}
			for _, addr := range remotePeerCert.IPAddresses {
				remoteSans = append(remoteSans, addr.String())
			}
			remoteConn = remoteTLSConn
			slog.Debug("Establishing client TLS connection", "remote", remoteAddr)
			clientConn = tls.Server(rawClientConn, getServerTLSConfig(remotePeerCert.Subject.CommonName, remoteSans))
			slog.Debug("Client TLS connection established, piping data", "remote", remoteAddr)
		} else {
			slog.Debug("Establishing cleartext connection", "remote", remoteAddr)
			remoteConn, err = net.Dial("tcp", remoteAddr)
			if err != nil {
				slog.Error("Failed to establish connection", "remote", remoteAddr)
				if req.Method == http.MethodConnect {
					errorResponse.Write(rawClientConn)
				}
				return
			}
			slog.Debug("Connected to remote", "remote", remoteAddr)
			clientConn = rawClientConn
		}
		if req.Method == http.MethodConnect {
			successResponse.Write(rawClientConn)
		} else {
			remoteConn.Write(reqBuf.Bytes())
		}
		var wg sync.WaitGroup
		wg.Go(func() {
			defer remoteConn.Close()
			if _, err := io.Copy(remoteConn, clientConn); err != nil {
				slog.Debug("Error while piping response to client", "remote", remoteAddr, "err", err)
			}
			slog.Debug("Client sent EOF", "remote", remoteAddr, "client", clientConn.RemoteAddr())
		})
		wg.Go(func() {
			defer clientConn.Close()
			if _, err := io.Copy(clientConn, remoteConn); err != nil {
				slog.Debug("Error while piping request to remote", "remote", remoteAddr, "err", err)
			}
			slog.Debug("Remote sent EOF", "remote", remoteAddr)
		})
		wg.Wait()
		slog.Debug("Request completed", "remote", remoteAddr)
	}

	return handleRequest, nil
}

func signCertificate(caCert *tls.Certificate, commonName string, sans []string) (*tls.Certificate, error) {
	key, err := stepKey.GenerateDefaultSigner()
	if err != nil {
		return nil, err
	}
	csr, err := stepX509.CreateCertificateRequest(commonName, sans, key)
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
	slog.Debug("Loading key/cert", "kuri", kuri)
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
