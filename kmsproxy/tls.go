package kmsproxy

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

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

func (proxy *Proxy) getProxiedTLSConfig(remotePeerCert *x509.Certificate) (*tls.Config, error) {
	generate, _ := proxy.tlsConfigMutexes.LoadOrStore(sha256.Sum256(remotePeerCert.Raw), sync.OnceValues(func() (*tls.Config, error) {
		slog.Debug("Generating cert", "CN", remotePeerCert.Subject.CommonName)
		remoteSans := []string{}
		for _, addr := range remotePeerCert.DNSNames {
			remoteSans = append(remoteSans, addr)
		}
		for _, addr := range remotePeerCert.IPAddresses {
			remoteSans = append(remoteSans, addr.String())
		}
		cert, err := proxy.SignCertificate(remotePeerCert.Subject.CommonName, remoteSans)
		if err != nil {
			return nil, err
		}
		config := &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
		}
		return config, nil
	}))
	return generate.(func() (*tls.Config, error))()
}

func (proxy *Proxy) ListenTLS(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	sans := []string{host}
	if host == "localhost" {
		sans = append(sans, "127.0.0.1")
	}
	servingCert, err := proxy.SignCertificate(host, sans)
	if err != nil {
		return nil, err
	}
	return tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{*servingCert},
		MinVersion:   tls.VersionTLS12,
	})
}

func (proxy *Proxy) SignCertificate(commonName string, sans []string) (*tls.Certificate, error) {
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
	cert, err := stepX509.CreateCertificate(tpl, proxy.ca.Leaf, tpl.PublicKey, proxy.ca.PrivateKey.(crypto.Signer))
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
	if _, err := os.Stat(kuri); err == nil {
		if certPath == nil {
			return nil, fmt.Errorf("You must specify a certificate when providing a certificate key as a path")
		}
		keyCert, err := tls.LoadX509KeyPair(*certPath, kuri)
		if err != nil {
			return nil, err
		}
		return &keyCert, nil
	}
	km, err := openKMS(ctx, kuri)
	if err != nil {
		return nil, fmt.Errorf("unable to open KMS using URI %s: %w", kuri, err)
	}
	cm, ok := km.(stepKMSAPI.CertificateChainManager)
	if !ok {
		return nil, fmt.Errorf("unable to load certificates from KMS: %s", km)
	}
	var rawCerts [][]byte
	var certPathLog string
	if certPath == nil {
		certPathLog = kuri
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
		certPathLog = *certPath
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
	keyCert := tls.Certificate{
		Certificate: rawCerts,
		PrivateKey:  key,
	}
	if keyCert.Leaf, err = x509.ParseCertificate(keyCert.Certificate[0]); err != nil {
		return nil, fmt.Errorf("failed to parse certificate leaf in %s: %w", certPathLog, err)
	}
	return &keyCert, nil
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
