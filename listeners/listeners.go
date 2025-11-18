package listeners

import (
	"fmt"
	"net"
	"sync"
)

var listenerMap = new(sync.Map)

func init() {
	listenerMap.Store("unix", func(addr string) (net.Listener, error) {
		listener, err := net.Listen("unix", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to open listener on address %s:%s: %w", "unix", addr, err)
		}
		slog.Info("Listening on unix socket", "path", addr)
		defer listener.Close()
		return listener, nil
	})
	listenerMap.Store("tcp", func(addr string) (net.Listener, error) {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to open listener on address %s:%s: %w", "tcp", addr, err)
		}
		slog.Info("Listening on TCP socket", "addr", addr)
		return listener, nil
	})
}

func CreateListener(proto string, addr string) (net.Listener, error) {
	value, ok := listenerMap.Load(proto)
	if ok {
		return value.(func(addr string) (net.Listener, error))(addr)
	} else {
		return nil, fmt.Errorf("unknown protocol specified: %s", proto)
	}
}
