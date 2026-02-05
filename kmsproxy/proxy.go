package kmsproxy

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
)

type Proxy struct {
	ca               *tls.Certificate
	clientKeyMap     map[string]crypto.Signer
	clientCertMap    map[string][]x509.Certificate
	clientTLSConfig  *tls.Config
	tlsConfigMutexes *sync.Map
	PACFile          *string
}

func NewProxy(
	ctx context.Context,
	caKeyPath string,
	caCertPath string,
	trustBundlePaths []string,
	clientKeyPaths []string,
	clientCertPaths []string,
	insecureSkipVerify bool,
	pacFile *string,
) (*Proxy, error) {
	var err error
	ca, err := loadKeyCert(ctx, caKeyPath, caCertPath)
	if err != nil {
		return nil, err
	}
	trustPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("unable to load system certificates: %w", err)
	}
	for _, caBundlePath := range trustBundlePaths {
		rawBundle, err := os.ReadFile(caBundlePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA bundle at %s: %w", caBundlePath, err)
		}
		ok := trustPool.AppendCertsFromPEM(rawBundle)
		if !ok {
			return nil, fmt.Errorf("failed to append %s to the certificate store", caBundlePath)
		}
	}
	clientKeyMap := map[string]crypto.Signer{}
	for _, keyPath := range clientKeyPaths {
		clientKeyMap[keyPath] = nil
	}
	clientCertMap := map[string][]x509.Certificate{}
	for _, certPath := range clientCertPaths {
		clientCertMap[certPath] = nil
	}
	proxy := Proxy{
		ca:               ca,
		clientKeyMap:     clientKeyMap,
		clientCertMap:    clientCertMap,
		tlsConfigMutexes: &sync.Map{},
		clientTLSConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateFreelyAsClient,
			RootCAs:            trustPool,
			InsecureSkipVerify: insecureSkipVerify,
			ClientSessionCache: tls.NewLRUClientSessionCache(-1),
		},
		PACFile: pacFile,
	}
	if err := proxy.reloadClientKeyCerts(ctx); err != nil {
		return nil, err
	}
	proxy.warnExpired()
	return &proxy, nil
}
