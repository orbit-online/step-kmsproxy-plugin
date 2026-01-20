package kmsproxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"

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

var SuccessResponse = http.Response{StatusCode: 200, Status: "Connection Established", ProtoMajor: 1, ProtoMinor: 1}
var ErrorResponse = http.Response{StatusCode: 502, Status: "Connection Failed", ProtoMajor: 1, ProtoMinor: 1}
var UnsupportedResponse = http.Response{StatusCode: 405, Status: "Must CONNECT", ProtoMajor: 1, ProtoMinor: 1}

func (proxy *Proxy) Serve(addr string) error {

	listener, err := proxy.ListenTLS(addr)
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func(rawClientConn net.Conn) {
			defer rawClientConn.Close()
			slog.Debug("New request", "client", rawClientConn.RemoteAddr())

			req, err := http.ReadRequest(bufio.NewReader(rawClientConn))
			if err != nil {
				slog.Error("Error parsing HTTP request", "req", req, "err", err)
				return
			}
			if req.Method != http.MethodConnect {
				UnsupportedResponse.Write(rawClientConn)
			}
			remoteConn, err := tls.Dial("tcp", req.Host, proxy.clientTLSConfig)
			if err != nil {
				slog.Error("Failed to establish connection", "remote", req.Host)
				ErrorResponse.Write(rawClientConn)
				return
			}
			defer remoteConn.Close()
			slog.Debug("Connected to remote", "remote", req.Host)
			if len(remoteConn.ConnectionState().PeerCertificates) == 0 {
				slog.Error("No peer certificate received from remote", "remote", req.Host)
				return
			}
			proxiedTLSConfig, err := proxy.getProxiedTLSConfig(remoteConn.ConnectionState().PeerCertificates[0])
			if err != nil {
				slog.Error("Failed to establish connection", "remote", req.Host)
				ErrorResponse.Write(rawClientConn)
				return
			}
			SuccessResponse.Write(rawClientConn)
			slog.Debug("Establishing client TLS connection", "remote", req.Host)
			clientConn := tls.Server(rawClientConn, proxiedTLSConfig)
			slog.Debug("Client TLS connection established, piping data", "remote", req.Host)

			var wg sync.WaitGroup
			wg.Go(func() {
				defer remoteConn.Close()
				if _, err := io.Copy(remoteConn, clientConn); err != nil {
					slog.Debug("Error while piping response to client", "remote", req.Host, "err", err)
				}
				slog.Debug("Client sent EOF", "remote", req.Host, "client", clientConn.RemoteAddr())
			})
			wg.Go(func() {
				defer clientConn.Close()
				if _, err := io.Copy(clientConn, remoteConn); err != nil {
					slog.Debug("Error while piping request to remote", "remote", req.Host, "err", err)
				}
				slog.Debug("Remote sent EOF", "remote", req.Host)
			})
			wg.Wait()
			slog.Debug("Request completed", "remote", req.Host)
		}(conn)
	}
}
