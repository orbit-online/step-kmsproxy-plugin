package kmsproxy

import (
	"context"
	"net/http"
)

func (proxy *Proxy) ServePAC(ctx context.Context, addr string) error {
	pacListener, err := proxy.ListenTLS(addr)
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
