package listeners

import (
	"fmt"
	"net"

	"github.com/coreos/go-systemd/activation"
)

func init() {
	listenerMap.Store("systemd", func(addr string) (net.Listener, error) {
		listeners, err := activation.Listeners()
		if err != nil {
			return nil, fmt.Errorf("Failed to retrieve SystemD listeners: %w", err)
		}
		if len(listeners) != 1 {
			return nil, fmt.Errorf("Unexpected number of socket activation fds, got %d expected 1", len(listeners))
		}
		listener := listeners[0]
		fmt.Println("Listening through SystemD socket activation")
		return listener, nil
	})
}
