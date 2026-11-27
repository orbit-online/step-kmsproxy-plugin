//go:build windows

package kmsproxy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"
)

var (
	nCryptCreatePersistedKey = ncrypt.NewProc("NCryptCreatePersistedKey")
	nCryptFinalizeKey        = ncrypt.NewProc("NCryptFinalizeKey")
	nCryptDeleteKey          = ncrypt.NewProc("NCryptDeleteKey")
)

// createPCPKey creates an ECDSA P-256 key in the Platform Crypto Provider of
// this user, with pin if not empty, and deletes it when the test ends.
func createPCPKey(t *testing.T, pin string) string {
	t.Helper()
	b := make([]byte, 6)
	rand.Read(b)
	name := "kmsproxy-test-" + hex.EncodeToString(b)
	var prov, h uintptr
	if err := ncall("NCryptOpenStorageProvider", nCryptOpenStorageProvider, ptr(&prov), ptr(u16(pcpProviderName)), 0); err != nil {
		t.Fatal(err)
	}
	defer nCryptFreeObject.Call(prov)
	if err := ncall("NCryptCreatePersistedKey", nCryptCreatePersistedKey, prov, ptr(&h), ptr(u16("ECDSA_P256")), ptr(u16(name)), 0, 0); err != nil {
		t.Fatal(err)
	}
	if pin != "" {
		if err := setPIN(h, pin); err != nil {
			t.Fatal(err)
		}
	}
	if err := ncall("NCryptFinalizeKey", nCryptFinalizeKey, h, ncryptSilentFlag); err != nil {
		t.Fatal(err)
	}
	nCryptFreeObject.Call(h)
	t.Cleanup(func() {
		var prov, h uintptr
		if ncall("NCryptOpenStorageProvider", nCryptOpenStorageProvider, ptr(&prov), ptr(u16(pcpProviderName)), 0) != nil {
			return
		}
		defer nCryptFreeObject.Call(prov)
		if ncall("NCryptOpenKey", nCryptOpenKey, prov, ptr(&h), ptr(u16(name)), 0, ncryptSilentFlag) == nil {
			nCryptDeleteKey.Call(h, 0) // frees h
		}
	})
	return name
}

func checkSigns(t *testing.T, s crypto.Signer) {
	t.Helper()
	digest := sha256.Sum256([]byte("kmsproxy test"))
	sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("the signature doesn't verify")
	}
}

// TestPCPKey needs a TPM and costs one count of the TPM lockout (one wrong
// PIN): KMSPROXY_PCP_TEST=1 runs it.
func TestPCPKey(t *testing.T) {
	if os.Getenv("KMSPROXY_PCP_TEST") != "1" {
		t.Skip("KMSPROXY_PCP_TEST=1 runs it")
	}
	var answers []string
	var notes []string
	askPIN = func(_, note string) (string, error) {
		notes = append(notes, note)
		if len(answers) == 0 {
			return "", errPINCancelled
		}
		a := answers[0]
		answers = answers[1:]
		return a, nil
	}
	t.Cleanup(func() { askPIN = dialogPIN })

	t.Run("without a PIN, nothing is asked", func(t *testing.T) {
		name := createPCPKey(t, "")
		var keys tpmKeys
		s, err := loadKey(context.Background(), &keys, "pcp:key="+name)
		if err != nil {
			t.Fatal(err)
		}
		checkSigns(t, s)
		if len(notes) != 0 {
			t.Fatalf("asked %d times", len(notes))
		}
	})

	t.Run("a wrong PIN asks again, with a note", func(t *testing.T) {
		notes = nil
		answers = []string{"000000", "123456"}
		name := createPCPKey(t, "123456")
		var keys tpmKeys
		s, err := keys.loadPCP("pcp:key=" + name)
		if err != nil {
			t.Fatal(err)
		}
		checkSigns(t, s)
		if len(notes) != 2 || notes[0] != "" || notes[1] != wrongPINNote {
			t.Fatalf("notes %q", notes)
		}
		// Held: a second load asks nothing.
		if _, err := keys.loadPCP("pcp:key=" + name); err != nil || len(notes) != 2 {
			t.Fatalf("second load: %v, asked %d times", err, len(notes))
		}
	})

	t.Run("Cancel asks again only after pcpAskAgain", func(t *testing.T) {
		notes = nil
		answers = nil
		name := createPCPKey(t, "123456")
		var keys tpmKeys
		if _, err := keys.loadPCP("pcp:key=" + name); !errors.Is(err, errPINCancelled) {
			t.Fatalf("got %v", err)
		}
		if _, err := keys.loadPCP("pcp:key=" + name); !errors.Is(err, errPINCancelled) || len(notes) != 1 {
			t.Fatalf("got %v, asked %d times", err, len(notes))
		}
		keys.keys[name].failed = time.Now().Add(-pcpAskAgain)
		answers = []string{"123456"}
		s, err := keys.loadPCP("pcp:key=" + name)
		if err != nil || len(notes) != 2 {
			t.Fatalf("got %v, asked %d times", err, len(notes))
		}
		checkSigns(t, s)
	})

	t.Run("a key that lost its handle opens again", func(t *testing.T) {
		notes = nil
		answers = []string{"123456", "123456"}
		name := createPCPKey(t, "123456")
		var keys tpmKeys
		s, err := keys.loadPCP("pcp:key=" + name)
		if err != nil {
			t.Fatal(err)
		}
		// A handle without its PIN fails to sign, as after a resume.
		k := keys.keys[name]
		k.mu.Lock()
		k.close()
		if err := ncall("NCryptOpenStorageProvider", nCryptOpenStorageProvider, ptr(&k.prov), ptr(u16(pcpProviderName)), 0); err != nil {
			t.Fatal(err)
		}
		if err := ncall("NCryptOpenKey", nCryptOpenKey, k.prov, ptr(&k.h), ptr(u16(name)), 0, ncryptSilentFlag); err != nil {
			t.Fatal(err)
		}
		k.mu.Unlock()
		checkSigns(t, s)
		if len(notes) != 2 {
			t.Fatalf("asked %d times", len(notes))
		}
	})

	t.Run("no such key", func(t *testing.T) {
		var keys tpmKeys
		if _, err := keys.loadPCP("pcp:key=kmsproxy-test-missing"); err == nil {
			t.Fatal("no error")
		}
	})
}
