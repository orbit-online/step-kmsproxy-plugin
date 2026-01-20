package kmsproxy

import (
	"net/http"
)

func (proxy *Proxy) ServePAC(addr string) error {
	pacListener, err := proxy.ListenTLS(addr)
	if err != nil {
		return err
	}
	pacServer := http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			http.ServeFile(writer, req, *proxy.PACFile)
		}),
	}
	return pacServer.Serve(pacListener)
}
