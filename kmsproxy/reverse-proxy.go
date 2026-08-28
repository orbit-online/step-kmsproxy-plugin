package kmsproxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"
	"sync"
)

func (proxy *Proxy) ServeReverseProxyRequests(ctx context.Context, addr string, stripSuffixes []string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	tlsConfigMutexes := &sync.Map{}
	getTLSCert := func(remotePeerCert *x509.Certificate, commonName string) (*tls.Certificate, error) {
		generate, _ := tlsConfigMutexes.LoadOrStore(
			sha256.Sum256(slices.Concat(remotePeerCert.Raw, []byte(commonName))),
			sync.OnceValues(func() (*tls.Certificate, error) { return proxy.getReverseProxiedTLSCert(remotePeerCert, commonName) }))
		return generate.(func() (*tls.Certificate, error))()
	}

	go func() { <-ctx.Done(); listener.Close() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			slog.Debug("New reverse-proxy request", "client", conn.RemoteAddr())

			var (
				remoteConn *tls.Conn
				remoteHost string
				remoteAddr string
			)
			clientConn := tls.Server(conn, &tls.Config{
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					remoteHost = hello.ServerName
					var found bool
					for _, suffix := range stripSuffixes {
						if remoteHost, found = strings.CutSuffix(remoteHost, suffix); found {
							break
						}
					}
					remoteAddr = fmt.Sprintf("%s:%d", remoteHost, 443)

					remoteConn, err = tls.Dial("tcp", remoteAddr, proxy.clientTLSConfig)
					if err != nil {
						return nil, fmt.Errorf("Failed to establish TLS connection with remote %s, error: %w", remoteAddr, err)
					}
					slog.Debug("Connected to remote", "remote", remoteAddr)

					remotePeerCerts := remoteConn.ConnectionState().PeerCertificates
					if len(remotePeerCerts) == 0 {
						return nil, fmt.Errorf("No peer certificate received from remote %s", remoteAddr)
					}
					tlsCert, err := getTLSCert(remotePeerCerts[0], hello.ServerName)
					if err != nil {
						return nil, fmt.Errorf("Failed generating TLS proxy config, remote: %w, error :%w", remoteAddr, err)
					}
					return &tls.Config{
						Certificates: []tls.Certificate{*tlsCert},
						MinVersion:   tls.VersionTLS12,
					}, nil
				},
			})
			defer clientConn.Close()
			defer remoteConn.Close()
			clientConn.Handshake()

			slog.Debug("Client TLS connection established, piping data", "remote", remoteAddr)

			proxyServer := &http.Server{Handler: &httputil.ReverseProxy{
				Transport: &TLSConnRoundTripper{conn: remoteConn},
				Rewrite:   func(pr *httputil.ProxyRequest) { pr.Out.Host = remoteHost },
			}}
			defer proxyServer.Shutdown(ctx)
			if err := proxyServer.Serve(newConnectionHandoverListener(listener.Addr(), clientConn)); err != nil && err != net.ErrClosed {
				slog.Error("Error while piping data", "error", err)
			}
		}()
	}
}
