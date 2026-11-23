package kmsproxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Keys of the ssh-agent at $SSH_AUTH_SOCK, by comment: sshagentkms:<comment>,
// as go.step.sm/crypto/kms/sshagentkms names them. Its signer can't
// authenticate a TLS client with an ECDSA key: its public key is an
// ssh.PublicKey, which matches no certificate, and it has the agent sign the
// digest TLS hands it, which the agent hashes again. This signer has the
// public key itself and signs messages (crypto.MessageSigner), which TLS
// hands it whole, so the agent hashes them once. It connects to the agent for
// every signature, so the agent can restart or come and go meanwhile.

const agentKeyScheme = "sshagentkms:"

type agentKey struct {
	socket string
	key    ssh.PublicKey
	pub    crypto.PublicKey
	hash   crypto.Hash // the hash the agent signs with, 0 for Ed25519
}

var (
	_ crypto.Signer        = (*agentKey)(nil)
	_ crypto.MessageSigner = (*agentKey)(nil)
)

func dialAgent(socket string) (agent.ExtendedAgent, func(), error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh-agent: %w", err)
	}
	return agent.NewClient(conn), func() { conn.Close() }, nil
}

func loadAgentKey(uri string) (crypto.Signer, error) {
	comment := strings.TrimPrefix(uri, agentKeyScheme)
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, fmt.Errorf("%s: SSH_AUTH_SOCK is not set", uri)
	}
	ag, done, err := dialAgent(socket)
	if err != nil {
		return nil, err
	}
	defer done()
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("ssh-agent at %s: %w", socket, err)
	}
	for _, k := range keys {
		if k.Comment != comment {
			continue
		}
		pk, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", uri, err)
		}
		cpk, ok := pk.(ssh.CryptoPublicKey)
		if !ok {
			return nil, fmt.Errorf("%s: a %s key", uri, pk.Type())
		}
		key := &agentKey{socket: socket, key: pk, pub: cpk.CryptoPublicKey()}
		switch pub := key.pub.(type) {
		case *ecdsa.PublicKey:
			// The agent hashes with the hash of the curve (RFC 5656 6.2.1), and
			// TLS 1.2 may ask a P-384 or P-521 key for SHA-256: P-256 only.
			if pub.Curve != elliptic.P256() {
				return nil, fmt.Errorf("%s: a %s key, of the ECDSA keys only P-256 ones sign through the agent", uri, pk.Type())
			}
			key.hash = crypto.SHA256
		case ed25519.PublicKey:
		default:
			// An RSA key signs with PKCS #1 v1.5 through an agent, which TLS 1.3 refuses
			return nil, fmt.Errorf("%s: a %s key, only ECDSA P-256 and Ed25519 keys sign through the agent", uri, pk.Type())
		}
		return key, nil
	}
	return nil, fmt.Errorf("%s: the ssh-agent at %s holds no key with that comment", uri, socket)
}

func (k *agentKey) Public() crypto.PublicKey { return k.pub }

// Sign signs Ed25519 messages; the agent hashes what it signs, so it signs no
// digests.
func (k *agentKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if k.hash != 0 {
		return nil, errors.New("an ECDSA key of an ssh-agent signs messages, not digests")
	}
	return k.SignMessage(rand, msg, opts)
}

// SignMessage returns the signature of msg: ASN.1 over SHA-256 for ECDSA, the
// only hash the agent signs a P-256 key with, and raw for Ed25519.
func (k *agentKey) SignMessage(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != k.hash {
		return nil, fmt.Errorf("a %s key of an ssh-agent signs over %v only, not %v", k.key.Type(), k.hash, opts.HashFunc())
	}
	ag, done, err := dialAgent(k.socket)
	if err != nil {
		return nil, err
	}
	defer done()
	sig, err := ag.Sign(k.key, msg)
	if err != nil {
		return nil, fmt.Errorf("ssh-agent at %s: %w", k.socket, err)
	}
	if sig.Format != k.key.Type() {
		return nil, fmt.Errorf("ssh-agent: a %s signature for a %s key", sig.Format, k.key.Type())
	}
	if k.hash == 0 {
		return sig.Blob, nil
	}
	var rs struct{ R, S *big.Int } // RFC 5656 3.1.2: mpint r, mpint s
	if err := ssh.Unmarshal(sig.Blob, &rs); err != nil {
		return nil, fmt.Errorf("ssh-agent signature: %w", err)
	}
	return asn1.Marshal(rs)
}
