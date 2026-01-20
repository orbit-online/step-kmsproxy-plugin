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
	var wg errgroup.Group
	var resetTimer func(cert *x509.Certificate)

	updateClientCert := func(reason string) {
		slog.Info("Reloading client certificate", "reason", reason)
		client, err := loadKeyCert(ctx, proxy.clientKeyURI, proxy.clientCertPath)
		if err != nil {
			slog.Error("failed to load client certificate", "err", err)
		}
		proxy.clientTLSConfig.Certificates = []tls.Certificate{*client}
		resetTimer(client.Leaf)
	}

	minTimer := time.AfterFunc(60*time.Second, func() { updateClientCert("Previous reload yielded an expired client certificate") })
	minTimer.Stop()
	expiryTimer := time.AfterFunc(60*time.Second, func() { updateClientCert("Client certificate has expired") })
	resetTimer = func(cert *x509.Certificate) {
		reloadIn := time.Until(cert.NotAfter)
		if reloadIn <= 0 {
			slog.Warn("The client certificate has expired")
			minTimer.Reset(60 * time.Second)
		} else {
			expiryTimer.Reset(reloadIn)
		}
	}

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
