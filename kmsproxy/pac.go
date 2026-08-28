package kmsproxy

import (
	"context"
	"crypto/tls"
	"net/http"
)

func (proxy *Proxy) ServePAC(ctx context.Context, addr string) error {
	servingCert, err := proxy.SignCertificateForListenAddr(addr)
	if err != nil {
		return err
	}
	pacListener, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{*servingCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return err
	}
	defer pacListener.Close()
	pacServer := http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			http.ServeFile(writer, req, *proxy.pacFile)
		}),
	}
	go func() { <-ctx.Done(); pacServer.Shutdown(ctx) }()
	return pacServer.Serve(pacListener)
}
