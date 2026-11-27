//go:build linux

package kmsproxy

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// TPM key files are loaded once and held: signing through ssh-tpm-agent, or
// loading the key for every signature, is too slow for TLS. The PIN is asked
// for with SSH_ASKPASS. A load that failed, Cancel included, is not retried
// until a SIGHUP.

var (
	openTPM = func() (transport.TPMCloser, error) { return linuxtpm.Open("/dev/tpmrm0") }
	askPIN  = askPass
)

type tpmKey struct {
	signer crypto.Signer
	err    error
	close  func()
}

type tpmKeys struct {
	mu   sync.Mutex
	keys map[string]tpmKey
}

func (k *tpmKeys) load(path string, data []byte) (crypto.Signer, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	key, ok := k.keys[path]
	if !ok {
		key = loadTPMKey(path, data)
		if k.keys == nil {
			k.keys = map[string]tpmKey{}
		}
		k.keys[path] = key
	}
	return key.signer, key.err
}

func (*tpmKeys) loadPCP(keyURI string) (crypto.Signer, error) {
	return nil, fmt.Errorf("%s: keys of the Platform Crypto Provider are supported on Windows only", keyURI)
}

// reset forgets the keys, so the next load asks for their PINs again.
func (k *tpmKeys) reset() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, key := range k.keys {
		if key.close != nil {
			key.close()
		}
	}
	k.keys = nil
}

func loadTPMKey(path string, data []byte) tpmKey {
	key, err := keyfile.Decode(data)
	if err != nil {
		return tpmKey{err: fmt.Errorf("%s: %w", path, err)}
	}
	tpm, err := openTPM()
	if err != nil {
		return tpmKey{err: err}
	}
	prompt := "kmsproxy: PIN of " + path
	for {
		var pin []byte
		if key.HasAuth() {
			if pin, err = askPIN(prompt); err != nil {
				tpm.Close()
				return tpmKey{err: fmt.Errorf("%s: %w (systemctl --user reload kmsproxy asks again)", path, err)}
			}
		}
		h, err := loadHandle(tpm, key, pin)
		if key.HasAuth() && errors.Is(err, tpm2.TPMRCAuthFail) {
			prompt = "kmsproxy: wrong PIN, each one counts towards the TPM lockout. PIN of " + path
			continue
		}
		if err != nil {
			tpm.Close()
			return tpmKey{err: fmt.Errorf("%s: %w", path, err)}
		}
		s := keyfile.NewTPMHandleSignerFromKey(tpm, key, *h)
		return tpmKey{signer: &s, close: func() {
			tpm2.FlushContext{FlushHandle: h.Handle}.Execute(tpm)
			tpm.Close()
		}}
	}
}

// loadHandle loads key with pin and checks the PIN with a signature.
func loadHandle(tpm transport.TPMCloser, key *keyfile.TPMKey, pin []byte) (*tpm2.AuthHandle, error) {
	h, parent, err := keyfile.LoadKey(keyfile.NewTPMSession(tpm), key, nil)
	if err != nil {
		return nil, err
	}
	if keyfile.IsMSO(parent.Handle, keyfile.TPM_HT_TRANSIENT) {
		tpm2.FlushContext{FlushHandle: parent.Handle}.Execute(tpm)
	}
	h.Auth = tpm2.PasswordAuth(pin)
	s := keyfile.NewTPMHandleSignerFromKey(tpm, key, *h)
	digest := sha256.Sum256(nil)
	if _, err := s.Sign(nil, digest[:], crypto.SHA256); err != nil {
		tpm2.FlushContext{FlushHandle: h.Handle}.Execute(tpm)
		return nil, err
	}
	return h, nil
}

// askPass asks with SSH_ASKPASS, as ssh-tpm-agent does.
func askPass(prompt string) ([]byte, error) {
	prog := os.Getenv("SSH_ASKPASS")
	if prog == "" {
		return nil, errors.New("SSH_ASKPASS is not set")
	}
	out, err := exec.Command(prog, prompt).Output()
	if err != nil {
		return nil, fmt.Errorf("SSH_ASKPASS: %w", err)
	}
	return []byte(strings.TrimRight(string(out), "\r\n")), nil
}
