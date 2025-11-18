package listeners

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/coreos/go-systemd/activation"
)

func init() {
	listenerMap.Store("systemd", func(addr string) (net.Listener, error) {
		listeners, err := activation.Listeners()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve SystemD listeners: %w", err)
		}
		if len(listeners) != 1 {
			return nil, fmt.Errorf("unexpected number of socket activation fds, got %d expected 1", len(listeners))
		}
		listener := listeners[0]
		slog.Info("Listening through SystemD socket activation")
		return listener, nil
	})
}
