package kmsproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type Proxy struct {
	ca               *tls.Certificate
	clientKeyURI     string
	clientCertPath   *string
	clientTLSConfig  *tls.Config
	tlsConfigMutexes *sync.Map
	tlsConfigCache   map[[32]byte]*tls.Config
	PACFile          *string
}

func NewProxy(
	ctx context.Context,
	caKey string,
	caCert *string,
	trust []string,
	clientKey string,
	clientCert *string,
	insecureSkipVerify bool,
	pacFile *string,
) (*Proxy, error) {
	var err error
	ca, err := loadKeyCert(ctx, caKey, caCert)
	if err != nil {
		return nil, err
	}
	trustPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("unable to load system certificates: %w", err)
	}
	for _, caBundlePath := range trust {
		rawBundle, err := os.ReadFile(caBundlePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA bundle at %s: %w", caBundlePath, err)
		}
		ok := trustPool.AppendCertsFromPEM(rawBundle)
		if !ok {
			return nil, fmt.Errorf("failed to append %s to the certificate store", caBundlePath)
		}
	}
	client, err := loadKeyCert(ctx, clientKey, clientCert)
	if err != nil {
		return nil, err
	}
	if client.Leaf.NotAfter.Compare(time.Now()) < 1 {
		slog.Warn("The client certificate has expired", "NotAfter", client.Leaf.NotAfter)
	}
	return &Proxy{
		ca:               ca,
		clientKeyURI:     clientKey,
		clientCertPath:   clientCert,
		tlsConfigMutexes: &sync.Map{},
		tlsConfigCache:   map[[32]byte]*tls.Config{},
		clientTLSConfig: &tls.Config{
			Certificates:       []tls.Certificate{*client},
			Renegotiation:      tls.RenegotiateFreelyAsClient,
			RootCAs:            trustPool,
			InsecureSkipVerify: insecureSkipVerify,
			ClientSessionCache: tls.NewLRUClientSessionCache(-1),
		},
		PACFile: pacFile,
	}, nil
}

func (proxy *Proxy) WatchClientCert(ctx context.Context, sigs chan os.Signal) error {
	var minTimer *time.Timer
	var expiryTimer *time.Timer
	retryInterval := time.Second * 60

	updateClientCert := func(reason string) {
		slog.Info("Reloading client certificate", "reason", reason)
		client, err := loadKeyCert(ctx, proxy.clientKeyURI, proxy.clientCertPath)
		reloadIn := retryInterval
		if err != nil {
			slog.Error("failed to load client certificate", "err", err)
		} else {
			proxy.clientTLSConfig.Certificates = []tls.Certificate{*client}
			reloadIn = time.Until(client.Leaf.NotAfter)
			if reloadIn.Seconds() <= 0 {
				slog.Warn("The client certificate is expired", "NotAfter", client.Leaf.NotAfter)
			}
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
		func() { updateClientCert("Client certificate has expired") },
	)
	reloadIn := time.Until(proxy.clientTLSConfig.Certificates[0].Leaf.NotAfter)
	if reloadIn.Seconds() <= 0 {
		expiryTimer.Stop()
	} else {
		minTimer.Stop()
		expiryTimer.Reset(reloadIn)
	}

	var wg errgroup.Group
	if proxy.clientCertPath != nil {
		wg.Go(func() error {
			slog.Info("Monitoring client certificate", "path", *proxy.clientCertPath)
			return WatchFile(*proxy.clientCertPath, func() { updateClientCert("Client certificate file changed") })
		})
	}

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
