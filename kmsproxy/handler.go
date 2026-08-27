package kmsproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"

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
	"golang.org/x/sync/errgroup"
)

var SuccessResponse = http.Response{StatusCode: 200, Status: "Connection Established", ProtoMajor: 1, ProtoMinor: 1}
var ErrorResponse = http.Response{StatusCode: 502, Status: "Connection Failed", ProtoMajor: 1, ProtoMinor: 1}
var UnsupportedResponse = http.Response{StatusCode: 405, Status: "Must CONNECT", ProtoMajor: 1, ProtoMinor: 1}

func (proxy *Proxy) Serve(ctx context.Context, addr string) error {
	listener, err := proxy.ListenTLS(addr)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); listener.Close() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			if err := proxy.handleProxyConnection(ctx, conn); err != nil {
				slog.Error(err.Error())
			}
		}()
	}
}

func (proxy *Proxy) handleProxyConnection(ctx context.Context, rawClientConn net.Conn) error {
	defer rawClientConn.Close()
	slog.Debug("New request", "client", rawClientConn.RemoteAddr())

	req, err := http.ReadRequest(bufio.NewReader(rawClientConn))
	if err != nil {
		return fmt.Errorf("Error parsing HTTP request, req: %s, error: %w", req, err)
	}
	if req.Method != http.MethodConnect {
		UnsupportedResponse.Write(rawClientConn)
		return fmt.Errorf("Method was not CONNECT")
	}
	remoteConn, err := tls.Dial("tcp", req.Host, proxy.clientTLSConfig)
	if err != nil {
		ErrorResponse.Write(rawClientConn)
		return fmt.Errorf("Failed to establish TLS connection with remote, remote: %s, error: %w", req.Host, err)
	}
	defer remoteConn.Close()
	slog.Debug("Connected to remote", "remote", req.Host)
	if len(remoteConn.ConnectionState().PeerCertificates) == 0 {
		return fmt.Errorf("No peer certificate received from remote, remote: %s", req.Host)
	}
	proxiedTLSConfig, err := proxy.getProxiedTLSConfig(remoteConn.ConnectionState().PeerCertificates[0])
	if err != nil {
		ErrorResponse.Write(rawClientConn)
		return fmt.Errorf("Failed generating TLS proxy config, remote: %w, error :%w", req.Host, err)
	}
	SuccessResponse.Write(rawClientConn)
	slog.Debug("Establishing client TLS connection", "remote", req.Host)
	clientConn := tls.Server(rawClientConn, proxiedTLSConfig)
	slog.Debug("Client TLS connection established, piping data", "remote", req.Host)

	wg, copyCtx := errgroup.WithContext(ctx)
	clientEOF := make(chan struct{})
	wg.Go(func() error {
		defer func() { clientEOF <- struct{}{} }()
		if _, err := io.Copy(remoteConn, clientConn); err != nil {
			return fmt.Errorf("Error while piping response to client, remote: %s, error: %w", req.Host, err)
		}
		slog.Debug("Client sent EOF", "remote", req.Host, "client", clientConn.RemoteAddr())
		return nil
	})
	remoteEOF := make(chan struct{})
	wg.Go(func() error {
		defer func() { remoteEOF <- struct{}{} }()
		if _, err := io.Copy(clientConn, remoteConn); err != nil {
			return fmt.Errorf("Error while piping request to remote, remote: %s, error: %w", req.Host, err)
		}
		slog.Debug("Remote sent EOF", "remote", req.Host)
		return nil
	})
	wg.Go(func() error {
		defer remoteConn.Close()
		defer rawClientConn.Close()
		defer clientConn.Close()
		select {
		case <-copyCtx.Done():
			return copyCtx.Err()
		case <-remoteEOF:
			remoteConn.Close()
			select {
			case <-copyCtx.Done():
				return copyCtx.Err()
			case <-clientEOF:
				slog.Info("all done")
				return nil
			}
		case <-clientEOF:
			rawClientConn.Close()
			clientConn.Close()
			select {
			case <-copyCtx.Done():
				return copyCtx.Err()
			case <-remoteEOF:
				slog.Info("all done")
				return nil
			}
		}
	})
	return wg.Wait()
}
