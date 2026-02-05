package kmsproxy

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"

	stepCLI "github.com/smallstep/cli-utils/step"
	stepKey "go.step.sm/crypto/keyutil"
	stepKMS "go.step.sm/crypto/kms"
	stepKMSAPI "go.step.sm/crypto/kms/apiv1"
	stepPEM "go.step.sm/crypto/pemutil"
)

func (proxy *Proxy) reloadClientKeyCerts(ctx context.Context) error {
	for keyPath, _ := range proxy.clientKeyMap {
		key, err := loadKey(ctx, keyPath)
		if err != nil {
			slog.Error("Failed to load certificate", "path", keyPath, "err", err)
		}
		proxy.clientKeyMap[keyPath] = key
	}
	for certPath, _ := range proxy.clientCertMap {
		cert, err := loadCert(ctx, certPath)
		if err != nil {
			slog.Error("Failed to load certificate", "path", certPath, "err", err)
		}
		proxy.clientCertMap[certPath] = cert
	}
	keyCerts, unmatchedKeys, unmatchedCerts := matchKeysAndCerts(proxy.clientKeyMap, proxy.clientCertMap)
	if len(unmatchedKeys) > 0 {
		slog.Warn(
			"Unable to match all keys to certificates",
			"keyPaths", slices.Collect(maps.Keys(unmatchedKeys)),
		)
	}
	if len(unmatchedCerts) > 0 {
		slog.Warn(
			"Unable to match all certificates to keys",
			"certPaths", slices.Collect(maps.Keys(unmatchedCerts)),
		)
	}
	if len(keyCerts) == 0 {
		slog.Error(
			"Unable to match any certificates to keys",
			"keyPaths", slices.Collect(maps.Keys(unmatchedKeys)),
			"certPaths", slices.Collect(maps.Keys(unmatchedCerts)),
		)
	}
	proxy.clientTLSConfig.Certificates = keyCerts
	return nil
}

func loadKeyCert(ctx context.Context, keyPath string, certPath string) (*tls.Certificate, error) {
	key, err := loadKey(ctx, keyPath)
	if err != nil {
		return nil, err
	}
	certBundle, err := loadCert(ctx, certPath)
	if err != nil {
		return nil, err
	}
	if !stepKey.Equal(key.Public(), certBundle[0].PublicKey) {
		return nil, fmt.Errorf("the key in %s does not match the first certificate in %s ", keyPath, certPath)
	}
	rawBundle := [][]byte{}
	for _, cert := range certBundle {
		rawBundle = append(rawBundle, cert.Raw)
	}
	return &tls.Certificate{
		Certificate: rawBundle,
		PrivateKey:  key,
		Leaf:        &certBundle[0],
	}, nil
}

func matchKeysAndCerts(keys map[string]crypto.Signer, certs map[string][]x509.Certificate) ([]tls.Certificate, map[string]crypto.Signer, map[string][]x509.Certificate) {
	keyCerts := []tls.Certificate{}
	unmatchedKeys := map[string]crypto.Signer{}
	matchedCerts := []string{}
	for keyPath, key := range keys {
		keyMatched := false
		if key != nil {
			for certPath, certBundle := range certs {
				if certBundle != nil {
					if stepKey.Equal(key.Public(), certBundle[0].PublicKey) {
						keyMatched = true
						matchedCerts = append(matchedCerts, certPath)
						rawBundle := [][]byte{}
						for _, cert := range certBundle {
							rawBundle = append(rawBundle, cert.Raw)
						}
						keyCerts = append(keyCerts, tls.Certificate{
							Certificate: rawBundle,
							PrivateKey:  key,
							Leaf:        &certBundle[0],
						})
					}
				}
			}
		}
		if !keyMatched {
			unmatchedKeys[keyPath] = key
		}
	}
	unmatchedCerts := map[string][]x509.Certificate{}
	for certPath, certBundle := range certs {
		if !slices.Contains(matchedCerts, certPath) {
			unmatchedCerts[certPath] = certBundle
		}
	}
	return keyCerts, unmatchedKeys, unmatchedCerts
}

func loadKey(ctx context.Context, keyPath string) (crypto.Signer, error) {
	slog.Debug("Loading key", "keyPath", keyPath)
	if _, err := os.Stat(keyPath); err == nil {
		rawKey, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key at %s: %w", keyPath, err)
		}
		maybeKey, err := stepPEM.Parse(rawKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key in %s (expected PEM formatting): %w", keyPath, err)
		}
		key, ok := maybeKey.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%s does not contain a private key", keyPath)
		}
		return key, nil
	} else {
		km, err := openKMS(ctx, keyPath)
		if err != nil {
			return nil, fmt.Errorf("file does not exist and unable to open as KMS using URI %s: %w", keyPath, err)
		}
		key, err := km.CreateSigner(&stepKMSAPI.CreateSignerRequest{
			SigningKey: keyPath,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to load private key using KMS URI %s: %w", keyPath, err)
		}
		return key, nil
	}
}

func loadCert(ctx context.Context, certPath string) ([]x509.Certificate, error) {
	slog.Debug("Loading cert", "certPath", certPath)
	var chain []x509.Certificate
	if _, err := os.Stat(certPath); err == nil {
		rawBundle, err := os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate at %s: %w", certPath, err)
		}
		var certPart *pem.Block
		var part = 0
		for {
			part++
			certPart, rawBundle = pem.Decode(rawBundle)
			if certPart == nil {
				break
			}
			if certPart.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("Part %d in %s is of type %s, not CERTIFICATE", part, certPath, certPart.Type)
			}
			cert, err := x509.ParseCertificate(certPart.Bytes)
			if err != nil {
				return nil, fmt.Errorf("Failed to parse part %d in %s as certificate: %w", part, certPath, err)
			}
			chain = append(chain, *cert)
		}
	} else {
		km, err := openKMS(ctx, certPath)
		if err != nil {
			return nil, fmt.Errorf("file does not exist and unable to open as KMS using URI %s: %w", certPath, err)
		}
		cm, ok := km.(stepKMSAPI.CertificateChainManager)
		if !ok {
			return nil, fmt.Errorf("unable to load certificates from KMS: %s", km)
		}
		cert, err := cm.LoadCertificateChain(&stepKMSAPI.LoadCertificateChainRequest{
			Name: certPath,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to load certificates from KMS URI %s: %w", certPath, err)
		}
		for part, c := range cert {
			cert, err := x509.ParseCertificate(c.Raw)
			if err != nil {
				return nil, fmt.Errorf("failed to parse part %d in %s as certificate: %w", part, certPath, err)
			}
			chain = append(chain, *cert)
		}
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates could be loaded from %s", certPath)
	}
	return chain, nil
}

// Source: https://github.com/smallstep/step-kms-plugin/blob/3be48fd238cdc1d40dfad5e6410cf852544c3b4f/cmd/root.go#L74-L94
func openKMS(ctx context.Context, kuri string) (stepKMSAPI.KeyManager, error) {
	typ, err := stepKMSAPI.TypeOf(kuri)
	if err != nil {
		return nil, err
	}

	var storageDirectory string
	if typ == stepKMSAPI.TPMKMS {
		if err := stepCLI.Init(); err != nil {
			return nil, err
		}
		storageDirectory = filepath.Join(stepCLI.Path(), "tpm")
	}

	// Type is not necessary, but it avoids an extra validation
	return stepKMS.New(ctx, stepKMSAPI.Options{
		Type:             typ,
		URI:              kuri,
		StorageDirectory: storageDirectory,
	})
}
