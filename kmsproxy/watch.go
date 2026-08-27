package kmsproxy

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

func (proxy *Proxy) SetupWatchers(ctx context.Context) (reload func(reason string)) {
	var retryTimer *time.Timer
	var expiryTimer *time.Timer
	retryInterval := time.Second * 60

	reload = func(reason string) {
		slog.Info("Reloading client keys and certificates", "reason", reason)
		reloadIn := retryInterval
		err := proxy.reloadClientKeyCerts(ctx)
		if err != nil {
			slog.Error("failed to load client certificate", "err", err)
		} else {
			proxy.warnExpired()
			reloadIn = time.Until(proxy.getEarliestClientCertExpiry())
		}
		if reloadIn.Seconds() <= 0 {
			expiryTimer.Stop()
			retryTimer.Reset(retryInterval)
		} else {
			retryTimer.Stop()
			expiryTimer.Reset(reloadIn)
		}
	}

	retryTimer = time.AfterFunc(
		retryInterval,
		func() { reload("Previous reload yielded an expired client certificate") },
	)
	expiryTimer = time.AfterFunc(
		retryInterval,
		func() { reload("A client certificate has expired") },
	)
	reloadIn := time.Until(proxy.getEarliestClientCertExpiry())
	if reloadIn.Seconds() <= 0 {
		expiryTimer.Stop()
	} else {
		retryTimer.Stop()
		expiryTimer.Reset(reloadIn)
	}

	for keyPath, _ := range proxy.clientKeyMap {
		proxy.pathNotifier.AddFunc(keyPath, func() { reload(fmt.Sprintf("%s changed", keyPath)) })
	}
	for certPath, _ := range proxy.clientCertMap {
		proxy.pathNotifier.AddFunc(certPath, func() { reload(fmt.Sprintf("%s changed", certPath)) })
	}
	return reload
}
