package kmsproxy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	stepKey "go.step.sm/crypto/keyutil"
	"golang.org/x/crypto/ssh/agent"
)

// serveAgent serves an in-memory ssh-agent holding keys (by comment) at
// $SSH_AUTH_SOCK, in a short directory: socket paths are limited to 108 bytes.
func serveAgent(t *testing.T, keys map[string]crypto.PrivateKey) {
	dir, err := os.MkdirTemp("/tmp", "kmsproxy-agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	keyring := agent.NewKeyring()
	for comment, k := range keys {
		if err := keyring.Add(agent.AddedKey{PrivateKey: k, Comment: comment}); err != nil {
			t.Fatal(err)
		}
	}
	sock := filepath.Join(dir, "agent")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { agent.ServeAgent(keyring, c); c.Close() }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
}

func selfSigned(t *testing.T, priv crypto.Signer) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client", Organization: []string{"observability"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestAgentKeyMTLS(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]crypto.Signer{"p256": p256, "ed25519": ed}
	agentKeys := map[string]crypto.PrivateKey{}
	for c, k := range keys {
		agentKeys[c] = k
	}
	agentKeys["p384"] = p384
	serveAgent(t, agentKeys)
	if _, err := loadKey(context.Background(), &tpmKeys{}, "sshagentkms:p384"); err == nil {
		t.Fatal("a P-384 agent key loaded")
	}

	for comment, priv := range keys {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			cert := selfSigned(t, priv)
			signer, err := loadKey(context.Background(), &tpmKeys{}, "sshagentkms:"+comment)
			if err != nil {
				t.Fatalf("%s: %v", comment, err)
			}
			if !stepKey.Equal(signer.Public(), cert.PublicKey) {
				t.Fatalf("%s: the agent key doesn't match its certificate", comment)
			}
			pool := x509.NewCertPool()
			pool.AddCert(cert)
			var seen string
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = r.TLS.PeerCertificates[0].Subject.Organization[0]
			}))
			srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MaxVersion: version}
			srv.StartTLS()
			c := srv.Client()
			c.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{
				{Certificate: [][]byte{cert.Raw}, PrivateKey: signer, Leaf: cert},
			}
			resp, err := c.Get(srv.URL)
			srv.Close()
			if err != nil {
				t.Fatalf("%s, TLS %x: %v", comment, version, err)
			}
			resp.Body.Close()
			if seen != "observability" {
				t.Fatalf("%s, TLS %x: the server saw O %q", comment, version, seen)
			}
		}
	}
}

func TestAgentKeyErrors(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	if _, err := loadKey(context.Background(), &tpmKeys{}, "sshagentkms:x"); err == nil {
		t.Fatal("no error without SSH_AUTH_SOCK")
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serveAgent(t, map[string]crypto.PrivateKey{"there": p256})
	if _, err := loadKey(context.Background(), &tpmKeys{}, "sshagentkms:missing"); err == nil {
		t.Fatal("no error for a comment the agent doesn't hold")
	}
	s, err := loadKey(context.Background(), &tpmKeys{}, "sshagentkms:there")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err == nil {
		t.Fatal("an ECDSA agent key signed a digest")
	}
	if _, err := s.(crypto.MessageSigner).SignMessage(rand.Reader, []byte("m"), crypto.SHA384); err == nil {
		t.Fatal("a P-256 agent key signed over SHA-384")
	}
}
