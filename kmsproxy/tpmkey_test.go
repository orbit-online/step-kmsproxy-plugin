//go:build linux

package kmsproxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
)

func TestTPMKey(t *testing.T) {
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not on PATH")
	}
	dir, _ := os.MkdirTemp("/tmp", "swtpm-") // a Unix socket path is short
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "sock")
	swtpm := exec.Command("swtpm", "socket", "--tpm2", "--tpmstate", "dir="+dir,
		"--server", "type=unixio,path="+sock, "--flags", "not-need-init,startup-clear")
	if err := swtpm.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { swtpm.Process.Kill(); swtpm.Wait() })
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	openTPM = func() (transport.TPMCloser, error) { return linuxudstpm.Open(sock) }

	// A key with a PIN, as ssh-tpm-keygen -p leaves it
	tpm, err := openTPM()
	if err != nil {
		t.Fatal(err)
	}
	k, err := keyfile.NewLoadableKey(tpm, tpm2.TPMAlgECC, 256, nil)
	if err == nil {
		err = keyfile.ChangeAuth(tpm, nil, k, nil, []byte("1234"))
	}
	tpm.Close()
	if err != nil {
		t.Fatal(err)
	}

	var answers []string
	asked := 0
	askPIN = func(string) ([]byte, error) {
		asked++
		a := answers[0]
		answers = answers[1:]
		if a == "cancel" {
			return nil, errors.New("cancelled")
		}
		return []byte(a), nil
	}
	var keys tpmKeys
	defer keys.reset()

	// A wrong PIN asks again; the key is then held
	answers = []string{"0000", "1234"}
	s, err := keys.load("key", k.Bytes())
	if err != nil || asked != 2 {
		t.Fatalf("%v, asked %d times", err, asked)
	}
	digest := sha256.Sum256([]byte("x"))
	sig, err := s.Sign(nil, digest[:], crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatalf("signature: %v", err)
	}
	if _, err := keys.load("key", k.Bytes()); err != nil || asked != 2 {
		t.Fatalf("a reload asked again: %v", err)
	}

	// Cancel sticks until reset (SIGHUP)
	keys.reset()
	answers = []string{"cancel", "1234"}
	for range 2 {
		if _, err := keys.load("key", k.Bytes()); err == nil || asked != 3 {
			t.Fatalf("after cancel: %v, asked %d times", err, asked)
		}
	}
	keys.reset()
	if _, err := keys.load("key", k.Bytes()); err != nil || asked != 4 {
		t.Fatalf("after reset: %v, asked %d times", err, asked)
	}
}
