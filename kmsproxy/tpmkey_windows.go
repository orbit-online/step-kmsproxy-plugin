//go:build windows

package kmsproxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"slices"
	"sync"
	"time"
	"unsafe"

	"go.step.sm/crypto/kms/uri"
	"golang.org/x/sys/windows"
)

// Keys of the Microsoft Platform Crypto Provider (the TPM) of this user,
// named by pcp:key=NAME, are opened once and held: the PIN of a key that has
// one is set on the handle, which keeps it. kmsproxy asks for the PIN in a
// credential dialog. A wrong PIN asks again at once, Cancel asks again after
// pcpAskAgain, and a key that fails to sign (after a resume) is opened again,
// asking for its PIN again. NCRYPT_SILENT_FLAG everywhere: Windows never
// shows a dialog of its own.

const (
	pcpProviderName = "Microsoft Platform Crypto Provider"
	pcpAskAgain     = time.Hour

	ncryptSilentFlag = 0x40
	nteBadKeyset     = 0x80090016 // NCryptOpenKey: no key of that name
	ntePerm          = 0x80090010 // a wrong PIN
	pcpAuthIgnored   = 0x80290409 // TPM_E_PCP_AUTHENTICATION_IGNORED: Windows blocks authorizations

	wrongPINNote = "Wrong PIN. Each wrong PIN counts: Windows blocks the TPM keys of a standard user after 4 within 8 hours."
)

var (
	ncrypt                    = windows.NewLazySystemDLL("ncrypt.dll")
	nCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	nCryptOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	nCryptGetProperty         = ncrypt.NewProc("NCryptGetProperty")
	nCryptSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	nCryptExportKey           = ncrypt.NewProc("NCryptExportKey")
	nCryptSignHash            = ncrypt.NewProc("NCryptSignHash")
	nCryptFreeObject          = ncrypt.NewProc("NCryptFreeObject")

	// askPIN asks for the PIN of the key name; note, if not empty, says why
	// it asks again. errPINCancelled when the user cancels.
	askPIN = dialogPIN
)

var errPINCancelled = errors.New("the PIN dialog was cancelled")

type tpmKeys struct {
	mu   sync.Mutex
	keys map[string]*pcpKey
}

func (*tpmKeys) load(path string, _ []byte) (crypto.Signer, error) {
	return nil, fmt.Errorf("%s: TPM key files are supported on Linux only, use %skey=NAME for a key of the Platform Crypto Provider", path, pcpKeyScheme)
}

// loadPCP opens the key that keyURI names, once; a key that failed to open
// is opened again after pcpAskAgain.
func (k *tpmKeys) loadPCP(keyURI string) (crypto.Signer, error) {
	u, err := uri.ParseWithScheme("pcp", keyURI)
	if err != nil {
		return nil, err
	}
	name := u.Get("key")
	if name == "" {
		return nil, fmt.Errorf("%s: no key name (%skey=NAME)", keyURI, pcpKeyScheme)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	key, ok := k.keys[name]
	if !ok {
		key = &pcpKey{name: name}
		if k.keys == nil {
			k.keys = map[string]*pcpKey{}
		}
		k.keys[name] = key
	}
	key.mu.Lock()
	defer key.mu.Unlock()
	if err := key.ensureOpen(); err != nil {
		return nil, err
	}
	return key, nil
}

// reset closes the keys, so the next load opens them again.
func (k *tpmKeys) reset() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, key := range k.keys {
		key.mu.Lock()
		key.close()
		key.mu.Unlock()
	}
	k.keys = nil
}

// pcpKey is a held PCP key and the crypto.Signer of it.
type pcpKey struct {
	name string
	mu   sync.Mutex
	prov uintptr
	h    uintptr
	pub  *ecdsa.PublicKey
	// err is why the last open failed, at failed; no open until pcpAskAgain
	// after it.
	err    error
	failed time.Time
}

func (k *pcpKey) Public() crypto.PublicKey {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.pub
}

// Sign signs with the held handle; when that fails, it opens the key again,
// asking for its PIN, and signs once more.
func (k *pcpKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.ensureOpen(); err != nil {
		return nil, err
	}
	sig, err := k.sign(digest)
	if err == nil {
		return sig, nil
	}
	slog.Warn("A TPM key failed to sign, opening it again", "key", k.name, "err", err)
	k.close()
	if err := k.ensureOpen(); err != nil {
		return nil, err
	}
	return k.sign(digest)
}

// ensureOpen opens the key unless it is open or failed less than
// pcpAskAgain ago. k.mu is held.
func (k *pcpKey) ensureOpen() error {
	if k.h != 0 {
		return nil
	}
	if k.err != nil && time.Since(k.failed) < pcpAskAgain {
		return k.err
	}
	if err := k.open(); err != nil {
		k.err, k.failed = fmt.Errorf("TPM key %s: %w (asks again at %s)", k.name, err, time.Now().Add(pcpAskAgain).Format(time.TimeOnly)), time.Now()
		return k.err
	}
	k.err = nil
	return nil
}

func (k *pcpKey) open() (err error) {
	if err := ncrypt.Load(); err != nil {
		return err
	}
	if err := ncall("NCryptOpenStorageProvider", nCryptOpenStorageProvider, ptr(&k.prov), ptr(u16(pcpProviderName)), 0); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			k.close()
		}
	}()
	err = ncall("NCryptOpenKey", nCryptOpenKey, k.prov, ptr(&k.h), ptr(u16(k.name)), 0, ncryptSilentFlag)
	if ne := (*ncryptError)(nil); errors.As(err, &ne) && ne.code == nteBadKeyset {
		return errors.New("no key of that name in the Platform Crypto Provider of this user")
	} else if err != nil {
		return err
	}
	pub, err := ecPublic(k.h)
	if err != nil {
		return err
	}
	k.pub = pub
	needsPIN, err := passwordRequired(k.h)
	if err != nil {
		return err
	}
	note := ""
	for {
		if needsPIN {
			pin, err := askPIN(k.name, note)
			if err != nil {
				return err
			}
			err = setPIN(k.h, pin)
			if err != nil {
				return err
			}
		}
		// A wrong PIN fails here, and not in a TLS handshake.
		digest := sha256.Sum256([]byte("kmsproxy: PIN check"))
		_, err := k.sign(digest[:])
		if ne := (*ncryptError)(nil); needsPIN && errors.As(err, &ne) && ne.code == ntePerm {
			slog.Warn("Wrong PIN for a TPM key", "key", k.name)
			note = wrongPINNote
			continue
		}
		return err
	}
}

func (k *pcpKey) close() {
	if k.h != 0 {
		nCryptFreeObject.Call(k.h)
		k.h = 0
	}
	if k.prov != 0 {
		nCryptFreeObject.Call(k.prov)
		k.prov = 0
	}
}

func (k *pcpKey) sign(digest []byte) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("empty digest")
	}
	size := uint32((k.pub.Curve.Params().BitSize + 7) / 8)
	sig := make([]byte, 2*size)
	var n uint32
	if err := ncall("NCryptSignHash", nCryptSignHash, k.h, 0, ptr(&digest[0]), uintptr(len(digest)), ptr(&sig[0]), uintptr(len(sig)), ptr(&n), ncryptSilentFlag); err != nil {
		return nil, pinError(err)
	}
	if n != 2*size {
		return nil, fmt.Errorf("NCryptSignHash: %d bytes of signature", n)
	}
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])})
}

// pinError explains the errors of a wrong PIN.
func pinError(err error) error {
	var ne *ncryptError
	switch {
	case errors.As(err, &ne) && ne.code == ntePerm:
		return fmt.Errorf("wrong PIN: %w", err)
	case errors.As(err, &ne) && ne.code == pcpAuthIgnored:
		return fmt.Errorf("Windows refuses TPM authorizations for now, after too many wrong PINs (4 within 8 hours for a standard user): %w", err)
	}
	return err
}

func u16(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		panic(err) // constant strings, and key names from a parsed URI
	}
	return p
}

func ptr[T any](p *T) uintptr { return uintptr(unsafe.Pointer(p)) }

// ncall calls an NCrypt function, which returns a SECURITY_STATUS.
func ncall(name string, p *windows.LazyProc, args ...uintptr) error {
	if r, _, _ := p.Call(args...); r != 0 {
		return &ncryptError{name, uint32(r)}
	}
	return nil
}

type ncryptError struct {
	call string
	code uint32
}

func (e *ncryptError) Error() string {
	return fmt.Sprintf("%s: 0x%08X (%v)", e.call, e.code, windows.Errno(e.code))
}

func getProperty(h uintptr, name string) ([]byte, error) {
	var size uint32
	if err := ncall("NCryptGetProperty "+name, nCryptGetProperty, h, ptr(u16(name)), 0, 0, ptr(&size), 0); err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	if err := ncall("NCryptGetProperty "+name, nCryptGetProperty, h, ptr(u16(name)), ptr(&buf[0]), uintptr(size), ptr(&size), 0); err != nil {
		return nil, err
	}
	return buf[:size], nil
}

// passwordRequired reports whether a key has a PIN (PCP_PASSWORD_REQUIRED).
func passwordRequired(h uintptr) (bool, error) {
	b, err := getProperty(h, "PCP_PASSWORD_REQUIRED")
	if err != nil {
		return false, err
	}
	// A BOOLEAN, of whatever size the PCP returns.
	return slices.ContainsFunc(b, func(c byte) bool { return c != 0 }), nil
}

// setPIN sets the PIN the handle uses for every operation on the key
// (NCRYPT_PIN_PROPERTY, with its terminating NUL).
func setPIN(h uintptr, pin string) error {
	w, err := windows.UTF16FromString(pin)
	if err != nil {
		return errors.New("the PIN has a NUL character")
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(&w[0])), len(w)*2)
	defer clear(b)
	return ncall("NCryptSetProperty SmartCardPin", nCryptSetProperty, h, ptr(u16("SmartCardPin")), ptr(&b[0]), uintptr(len(b)), 0)
}

// ecPublic exports the public key of an ECDSA key.
func ecPublic(h uintptr) (*ecdsa.PublicKey, error) {
	var size uint32
	if err := ncall("NCryptExportKey", nCryptExportKey, h, 0, ptr(u16("ECCPUBLICBLOB")), 0, 0, 0, ptr(&size), 0); err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	if err := ncall("NCryptExportKey", nCryptExportKey, h, 0, ptr(u16("ECCPUBLICBLOB")), 0, ptr(&buf[0]), uintptr(len(buf)), ptr(&size), 0); err != nil {
		return nil, err
	}
	// BCRYPT_ECCKEY_BLOB: dwMagic, cbKey, then X and Y.
	if size < 8 {
		return nil, errors.New("not an ECDSA key")
	}
	n := int(binary.LittleEndian.Uint32(buf[4:]))
	var curve elliptic.Curve
	switch n {
	case 32:
		curve = elliptic.P256()
	case 48:
		curve = elliptic.P384()
	case 66:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("an ECDSA key of %d-byte coordinates, not P-256, P-384 or P-521", n)
	}
	if int(size) != 8+2*n {
		return nil, errors.New("not an ECDSA key")
	}
	return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(buf[8 : 8+n]), Y: new(big.Int).SetBytes(buf[8+n:])}, nil
}

var (
	credui                     = windows.NewLazySystemDLL("credui.dll")
	credUIPromptForCredentials = credui.NewProc("CredUIPromptForCredentialsW")
)

// CREDUI_INFOW
type creduiInfo struct {
	cbSize         uint32
	hwndParent     uintptr
	pszMessageText *uint16
	pszCaptionText *uint16
	hbmBanner      uintptr
}

// CredUIPromptForCredentials flags (wincred.h).
const (
	creduiDoNotPersist       = 0x00002
	creduiAlwaysShowUI       = 0x00080
	creduiGenericCredentials = 0x40000
	creduiKeepUsername       = 0x100000
)

// dialogPIN asks for the PIN of the key name in a Windows credential dialog
// (see promptOwner for when it comes to the front): no console needed,
// nothing saved in the credential manager.
func dialogPIN(name, note string) (string, error) {
	msg := "The PIN of the TPM key " + name + ", for kmsproxy to sign the TLS connections it proxies."
	if note != "" {
		// The dialog drops line breaks.
		msg = note + " " + msg
	}
	owner, done := promptOwner("kmsproxy")
	defer done()
	info := creduiInfo{hwndParent: owner, pszMessageText: u16(msg), pszCaptionText: u16("kmsproxy")}
	info.cbSize = uint32(unsafe.Sizeof(info))
	user := make([]uint16, 514)
	copy(user, windows.StringToUTF16(name))
	pass := make([]uint16, 257)
	defer clear(pass)
	flags := uint32(creduiGenericCredentials | creduiAlwaysShowUI | creduiDoNotPersist | creduiKeepUsername)
	r, _, _ := credUIPromptForCredentials.Call(ptr(&info), ptr(u16("kmsproxy")), 0, 0,
		ptr(&user[0]), uintptr(len(user)), ptr(&pass[0]), uintptr(len(pass)), 0, uintptr(flags))
	switch windows.Errno(r) {
	case 0:
		return windows.UTF16ToString(pass), nil
	case windows.ERROR_CANCELLED:
		return "", errPINCancelled
	default:
		return "", fmt.Errorf("CredUIPromptForCredentials: %w", windows.Errno(r))
	}
}
