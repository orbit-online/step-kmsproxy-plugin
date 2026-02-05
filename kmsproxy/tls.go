package kmsproxy

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"sync"
	"time"

	stepKey "go.step.sm/crypto/keyutil"
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

func (proxy *Proxy) warnExpired() {
	for certPath, certBundle := range proxy.clientCertMap {
		if certBundle != nil && certBundle[0].NotAfter.Compare(time.Now()) < 1 {
			slog.Warn("A client certificate has expired", "NotAfter", certBundle[0].NotAfter, "path", certPath)
		}
	}
}

func (proxy *Proxy) getEarliestClientCertExpiry() time.Time {
	earliest := proxy.clientTLSConfig.Certificates[0].Leaf.NotAfter
	for _, cert := range proxy.clientTLSConfig.Certificates {
		if cert.Leaf.NotAfter.Before(earliest) {
			earliest = cert.Leaf.NotAfter
		}
	}
	return earliest
}
