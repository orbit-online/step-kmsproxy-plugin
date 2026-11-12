package kmsproxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	path_poller "github.com/orbit-online/go-path-poller"
	"github.com/orbit-online/step-kmsproxy-plugin/kmsproxy/gate"
)

type testEnv struct {
	proxy        *Proxy
	proxyAddr    string
	revAddr      string
	asked        chan askedGate
	proxyRoots   *x509.CertPool
	upstream     *httptest.Server
	upstreamConn atomic.Int32
}

// What the gate asked the user, and its answer
type askedGate struct {
	ctx     context.Context
	domains []string
}

// Starts an mTLS upstream and an HTTPS proxy holding a client cert for it, whose gate answers every question with answer
func newTestEnv(t *testing.T) *testEnv {
	return newGatedTestEnv(t, gate.AllowTemp)
}

func newGatedTestEnv(t *testing.T, answer gate.Answer) *testEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dir := t.TempDir()
	env := &testEnv{asked: make(chan askedGate, 16)}

	env.upstream = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	env.upstream.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	env.upstream.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			env.upstreamConn.Add(1)
		}
	}
	env.upstream.StartTLS()
	t.Cleanup(env.upstream.Close)
	writePEM(t, filepath.Join(dir, "upstream.crt"), "CERTIFICATE", env.upstream.Certificate().Raw)

	caKey, caCert := newCert(t, "proxy CA", nil, nil)
	writeKeyCert(t, dir, "ca", caKey, caCert)
	env.proxyRoots = x509.NewCertPool()
	env.proxyRoots.AddCert(caCert)
	clientKey, clientCert := newCert(t, "client", caKey, caCert)
	writeKeyCert(t, dir, "client", clientKey, clientCert)

	notifier, err := path_poller.NewPathNotifier()
	if err != nil {
		t.Fatal(err)
	}
	// Identification is tested in the gate package, and needs a cgroupfs the Nix build sandbox doesn't have
	identify := func(local, remote string) (gate.Caller, error) {
		return gate.Caller{ID: "test", Description: "test"}, nil
	}
	callerGate, err := gate.New(filepath.Join(dir, "allowed.json"), identify,
		func(ctx context.Context, caller gate.Caller, domains []string) (gate.Answer, error) {
			env.asked <- askedGate{ctx, domains}
			if answer == gate.Dismissed {
				<-ctx.Done()
			}
			return answer, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	env.proxy, err = NewProxy(ctx,
		filepath.Join(dir, "ca.key"), filepath.Join(dir, "ca.crt"),
		[]string{filepath.Join(dir, "upstream.crt")},
		[]string{filepath.Join(dir, "client.key")}, []string{filepath.Join(dir, "client.crt")},
		false, nil, notifier, callerGate)
	if err != nil {
		t.Fatal(err)
	}

	env.proxyAddr = freeAddr(t)
	go env.proxy.ServeHTTPSProxyRequests(ctx, env.proxyAddr)
	env.revAddr = freeAddr(t)
	upstreamPort := env.upstream.Listener.Addr().(*net.TCPAddr).Port
	go env.proxy.ServeReverseProxyRequests(ctx, env.revAddr, []string{".kmsproxy.internal"},
		map[string]int64{"localhost.kmsproxy.internal": int64(upstreamPort)})
	for _, addr := range []string{env.proxyAddr, env.revAddr} {
		for i := 0; ; i++ {
			if c, err := net.Dial("tcp", addr); err == nil {
				c.Close()
				break
			} else if i == 100 {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	return env
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return fmt.Sprintf("localhost:%d", l.Addr().(*net.TCPAddr).Port)
}

func (env *testEnv) question(t *testing.T) askedGate {
	t.Helper()
	select {
	case a := <-env.asked:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("the gate asked nothing")
		return askedGate{}
	}
}

func (env *testEnv) dialProxy(t *testing.T) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", env.proxyAddr, &tls.Config{RootCAs: env.proxyRoots, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

// GET through a CONNECT tunnel, returns the client CN the upstream saw.
func (env *testEnv) get(t *testing.T) string {
	conn := env.dialProxy(t)
	defer conn.Close()
	upstreamHost := env.upstream.Listener.Addr().String()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamHost, upstreamHost)
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Error(err)
		return ""
	}
	if res.StatusCode != 200 {
		t.Errorf("CONNECT: got %s", res.Status)
		return ""
	}
	tunnel := tls.Client(&bufferedConn{conn, br}, &tls.Config{RootCAs: env.proxyRoots, ServerName: "example.com"})
	if err := tunnel.Handshake(); err != nil {
		t.Error(err)
		return ""
	}
	fmt.Fprintf(tunnel, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upstreamHost)
	res, err = http.ReadResponse(bufio.NewReader(tunnel), nil)
	if err != nil {
		t.Error(err)
		return ""
	}
	body, _ := io.ReadAll(res.Body)
	return string(body)
}

func TestConnect(t *testing.T) {
	env := newTestEnv(t)
	if cn := env.get(t); cn != "client" {
		t.Fatalf("upstream saw client CN %q", cn)
	}
}

func TestGateRefusesConnect(t *testing.T) {
	env := newGatedTestEnv(t, gate.Deny)
	conn := env.dialProxy(t)
	defer conn.Close()
	upstreamHost := env.upstream.Listener.Addr().String()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamHost, upstreamHost)
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 403 {
		t.Errorf("got %s", res.Status)
	}
	if a := env.question(t); len(a.domains) != 1 || a.domains[0] != "127.0.0.1" {
		t.Errorf("asked about %v", a.domains)
	}
	if n := env.upstreamConn.Load(); n != 0 {
		t.Errorf("dialed the upstream %d times", n)
	}
}

func TestGateRefusesReverse(t *testing.T) {
	env := newGatedTestEnv(t, gate.Deny)
	conn, err := tls.Dial("tcp", env.revAddr, &tls.Config{RootCAs: env.proxyRoots, ServerName: "localhost.kmsproxy.internal"})
	if err == nil {
		conn.Close()
		t.Fatal("handshake succeeded")
	}
	if a := env.question(t); len(a.domains) != 1 || a.domains[0] != "localhost" {
		t.Errorf("asked about %v", a.domains)
	}
	if n := env.upstreamConn.Load(); n != 0 {
		t.Errorf("dialed the upstream %d times", n)
	}
}

// A client hanging up mid-handshake, while the gate waits for an answer, withdraws the question
func TestGateHangUpReverse(t *testing.T) {
	env := newGatedTestEnv(t, gate.Dismissed)
	raw, err := net.Dial("tcp", env.revAddr)
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(raw, &tls.Config{RootCAs: env.proxyRoots, ServerName: "localhost.kmsproxy.internal"})
	go client.Handshake()
	a := env.question(t)
	raw.Close()
	select {
	case <-a.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the question stayed up after the client hung up")
	}
}

func TestNonConnectIsRejected(t *testing.T) {
	env := newTestEnv(t)
	conn := env.dialProxy(t)
	defer conn.Close()
	upstreamHost := env.upstream.Listener.Addr().String()
	fmt.Fprintf(conn, "GET https://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamHost, upstreamHost)
	// The proxy should close the connection after the 405; a timeout here means it kept going.
	out, err := io.ReadAll(conn)
	if !strings.HasPrefix(string(out), "HTTP/1.1 405") {
		t.Errorf("expected a 405, got %q (read error: %v)", out, err)
	}
	if n := strings.Count(string(out), "HTTP/1.1 "); n != 1 {
		t.Errorf("expected one response, got %d: %q", n, out)
	}
	if n := env.upstreamConn.Load(); n != 0 {
		t.Errorf("proxy dialed the upstream %d times after a non-CONNECT request", n)
	}
}

// Under -race: reloading client certs must not race with connections dialing upstream.
func TestReloadDuringTraffic(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 20 {
			env.proxy.LoadClientKeyCerts(ctx, "test")
		}
	})
	for range 10 {
		wg.Go(func() {
			if cn := env.get(t); cn != "client" {
				t.Errorf("upstream saw client CN %q", cn)
			}
		})
	}
	wg.Wait()
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// Self-signed when parent is nil.
func newCert(t *testing.T, cn string, parentKey *ecdsa.PrivateKey, parent *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if parent == nil {
		tpl.IsCA, tpl.BasicConstraintsValid = true, true
		tpl.KeyUsage |= x509.KeyUsageCertSign
		tpl.ExtKeyUsage = nil
		parent, parentKey = tpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func writeKeyCert(t *testing.T, dir, name string, key *ecdsa.PrivateKey, cert *x509.Certificate) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, name+".key"), "PRIVATE KEY", der)
	writePEM(t, filepath.Join(dir, name+".crt"), "CERTIFICATE", cert.Raw)
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}
