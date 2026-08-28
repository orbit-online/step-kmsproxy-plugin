package kmsproxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"

	"golang.org/x/sync/errgroup"
)

var SuccessResponse = http.Response{StatusCode: 200, Status: "Connection Established", ProtoMajor: 1, ProtoMinor: 1}
var ErrorResponse = http.Response{StatusCode: 502, Status: "Connection Failed", ProtoMajor: 1, ProtoMinor: 1}
var UnsupportedResponse = http.Response{StatusCode: 405, Status: "Must CONNECT", ProtoMajor: 1, ProtoMinor: 1}

func (proxy *Proxy) ServeHTTPSProxyRequests(ctx context.Context, addr string) error {
	servingCert, err := proxy.SignCertificateForListenAddr(addr)
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{*servingCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return err
	}

	tlsConfigMutexes := &sync.Map{}
	getTLSCert := func(remotePeerCert *x509.Certificate) (*tls.Certificate, error) {
		generate, _ := tlsConfigMutexes.LoadOrStore(
			sha256.Sum256(remotePeerCert.Raw),
			sync.OnceValues(func() (*tls.Certificate, error) {
				return proxy.getProxiedTLSCert(remotePeerCert)
			}))
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
			slog.Debug("New proxy request", "client", conn.RemoteAddr())
			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				slog.Error(fmt.Errorf("Error parsing HTTP request, req: %s, error: %w", req, err).Error())
				return
			}
			if req.Method != http.MethodConnect {
				UnsupportedResponse.Write(conn)
				slog.Error("Method was not CONNECT")
			}

			remoteHost := req.Host

			remoteConn, err := tls.Dial("tcp", remoteHost, proxy.clientTLSConfig)
			if err != nil {
				ErrorResponse.Write(conn)
				slog.Error("Failed to establish TLS connection with remote", "remote", remoteHost, "error", err)
				return
			}
			defer remoteConn.Close()
			slog.Debug("Connected to remote", "remote", remoteHost)

			remotePeerCerts := remoteConn.ConnectionState().PeerCertificates
			if len(remotePeerCerts) == 0 {
				slog.Error("No peer certificate received from remote", "remote", remoteHost)
				return
			}
			tlsCert, err := getTLSCert(remotePeerCerts[0])
			if err != nil {
				ErrorResponse.Write(conn)
				slog.Error("Failed generating TLS certificate", "remote", remoteHost, "error", err)
				return
			}
			SuccessResponse.Write(conn)

			slog.Debug("Establishing client TLS connection", "remote", remoteHost)
			clientConn := tls.Server(conn, &tls.Config{
				Certificates: []tls.Certificate{*tlsCert},
				MinVersion:   tls.VersionTLS12,
			})

			slog.Debug("Client TLS connection established, piping data", "remote", remoteHost)
			wg, copyCtx := errgroup.WithContext(ctx)
			clientEOF := make(chan struct{})
			wg.Go(func() error {
				defer func() { clientEOF <- struct{}{} }()
				if _, err := io.Copy(remoteConn, clientConn); err != nil {
					return fmt.Errorf("Error while piping response to remote, remote addr: %s, error: %w", remoteConn.RemoteAddr(), err)
				}
				slog.Debug("Client sent EOF", "clientAddr", remoteConn.RemoteAddr(), "remoteAddr", clientConn.RemoteAddr())
				return nil
			})
			remoteEOF := make(chan struct{})
			wg.Go(func() error {
				defer func() { remoteEOF <- struct{}{} }()
				if _, err := io.Copy(clientConn, remoteConn); err != nil {
					return fmt.Errorf("Error while piping request to client, clientAddr: %s, error: %w", clientConn.RemoteAddr(), err)
				}
				slog.Debug("Remote sent EOF", "clientAddr", remoteConn.RemoteAddr(), "remoteAddr", clientConn.RemoteAddr())
				return nil
			})
			wg.Go(func() error {
				select {
				case <-copyCtx.Done():
					return copyCtx.Err()
				case <-remoteEOF:
					select {
					case <-copyCtx.Done():
						return copyCtx.Err()
					case <-clientEOF:
						return nil
					}
				case <-clientEOF:
					select {
					case <-copyCtx.Done():
						return copyCtx.Err()
					case <-remoteEOF:
						return nil
					}
				}
			})
			if err := wg.Wait(); err != nil {
				slog.Error(err.Error())
			}
		}()
	}
}
