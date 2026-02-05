package kmsproxy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/sync/errgroup"
)

func (proxy *Proxy) WatchPaths(ctx context.Context, sigs chan os.Signal) error {
	var minTimer *time.Timer
	var expiryTimer *time.Timer
	retryInterval := time.Second * 60

	updateClientCert := func(reason string) {
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
			minTimer.Reset(retryInterval)
		} else {
			minTimer.Stop()
			expiryTimer.Reset(reloadIn)
		}
	}

	minTimer = time.AfterFunc(
		retryInterval,
		func() { updateClientCert("Previous reload yielded an expired client certificate") },
	)
	expiryTimer = time.AfterFunc(
		retryInterval,
		func() { updateClientCert("A client certificate has expired") },
	)
	reloadIn := time.Until(proxy.getEarliestClientCertExpiry())
	if reloadIn.Seconds() <= 0 {
		expiryTimer.Stop()
	} else {
		minTimer.Stop()
		expiryTimer.Reset(reloadIn)
	}

	var wg errgroup.Group
	var watchList []string
	for keyPath, _ := range proxy.clientKeyMap {
		if _, err := os.Stat(keyPath); err == nil {
			watchList = append(watchList, keyPath)
		}
	}
	for certPath, _ := range proxy.clientCertMap {
		if _, err := os.Stat(certPath); err == nil {
			watchList = append(watchList, certPath)
		}
	}
	wg.Go(func() error {
		slog.Info("Monitoring client certificates & keys", "paths", watchList)
		return WatchFiles(watchList, func(path string) { updateClientCert(fmt.Sprintf("%s changed", path)) })
	})

	wg.Go(func() error {
		for {
			<-sigs
			updateClientCert("SIGHUP reload signal was sent")
		}
	})
	if err := wg.Wait(); err != nil {
		return err
	}
	return nil
}

func WatchFiles(paths []string, onChange func(path string)) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create filesystem watcher: %w", err)
	}
	defer watcher.Close()
	for _, path := range paths {
		err = watcher.Add(path)
		if err != nil {
			return fmt.Errorf("failed to watch path %s: %w", path, err)
		}
	}
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return fmt.Errorf("Watcher was closed")
			}
			onChange(event.Name)
			slog.Debug("File changed", "path", event.Name)
		case err, ok := <-watcher.Errors:
			if !ok {
				return fmt.Errorf("Watcher was closed")
			}
			slog.Warn("Error while watching for file changes", "err", err)
		}
	}
}
