//go:build !linux && !windows

package kmsproxy

import (
	"crypto"
	"fmt"
)

type tpmKeys struct{}

func (*tpmKeys) load(path string, _ []byte) (crypto.Signer, error) {
	return nil, fmt.Errorf("%s: TPM key files are supported on Linux only", path)
}

func (*tpmKeys) reset() {}

func (*tpmKeys) loadPCP(keyURI string) (crypto.Signer, error) {
	return nil, fmt.Errorf("%s: keys of the Platform Crypto Provider are supported on Windows only", keyURI)
}
