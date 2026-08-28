package kmsproxy

import (
	"bufio"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"log/slog"
	"net"
	"net/http"
	"slices"
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

func (proxy *Proxy) getReverseProxiedTLSCert(remotePeerCert *x509.Certificate, commonName string) (*tls.Certificate, error) {
	slog.Debug("Generating cert", "CN", commonName)
	key, err := stepKey.GenerateDefaultSigner()
	if err != nil {
		return nil, err
	}
	localPeerCert := *remotePeerCert
	localPeerCert.Subject.CommonName = commonName
	localPeerCert.RawSubject, err = asn1.Marshal(localPeerCert.Subject.ToRDNSequence())
	if err != nil {
		return nil, err
	}
	localPeerCert.SignatureAlgorithm = stepKey.DefaultSignatureAlgorithm
	localPeerCert.DNSNames = append(localPeerCert.DNSNames, commonName)
	if !slices.Contains(localPeerCert.DNSNames, remotePeerCert.Subject.CommonName) {
		localPeerCert.DNSNames = append(localPeerCert.DNSNames, remotePeerCert.Subject.CommonName)
	}
	newCert, err := stepX509.CreateCertificate(&localPeerCert, proxy.ca.Leaf, key.Public(), proxy.ca.PrivateKey.(crypto.Signer))
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{newCert.Raw},
		PrivateKey:  key,
	}, nil
}

func (proxy *Proxy) getProxiedTLSCert(remotePeerCert *x509.Certificate) (*tls.Certificate, error) {
	slog.Debug("Generating cert", "CN", remotePeerCert.Subject.CommonName)
	key, err := stepKey.GenerateDefaultSigner()
	if err != nil {
		return nil, err
	}
	localPeerCert := *remotePeerCert
	localPeerCert.SignatureAlgorithm = stepKey.DefaultSignatureAlgorithm
	newCert, err := stepX509.CreateCertificate(&localPeerCert, proxy.ca.Leaf, key.Public(), proxy.ca.PrivateKey.(crypto.Signer))
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{newCert.Raw},
		PrivateKey:  key,
	}, nil
}

func (proxy *Proxy) SignCertificateForListenAddr(addr string) (*tls.Certificate, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	sans := []string{host}
	if host == "localhost" {
		sans = append(sans, "127.0.0.1")
	}
	key, err := stepKey.GenerateDefaultSigner()
	if err != nil {
		return nil, err
	}
	csr, err := stepX509.CreateCertificateRequest(host, sans, key)
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

type ConnectionHandoverListener struct {
	addr       net.Addr
	clientConn net.Conn
	acceptMu   *sync.Mutex
	closed     chan error
}

func newConnectionHandoverListener(addr net.Addr, clientConn net.Conn) ConnectionHandoverListener {
	return ConnectionHandoverListener{
		addr:       addr,
		clientConn: clientConn,
		acceptMu:   &sync.Mutex{},
		closed:     make(chan error, 1),
	}
}
func (l ConnectionHandoverListener) Accept() (net.Conn, error) {
	if l.acceptMu.TryLock() {
		clientConn := l.clientConn
		l.clientConn = nil
		return clientConn, nil
	} else {
		if err, ok := <-l.closed; ok {
			return nil, err
		} else {
			return nil, net.ErrClosed
		}
	}
}
func (l ConnectionHandoverListener) Close() error {
	select {
	case l.closed <- net.ErrClosed:
	default:
	}
	close(l.closed)
	return l.clientConn.Close()
}
func (l ConnectionHandoverListener) Addr() net.Addr {
	return l.addr
}

type TLSConnRoundTripper struct {
	conn *tls.Conn
}

func (rt *TLSConnRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Write(rt.conn); err != nil {
		return nil, err
	}
	res, err := http.ReadResponse(bufio.NewReader(rt.conn), req)
	return res, err
}
