// i2p_keys.go
package i2pkeys

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
)

var (
    ErrInvalidKeyType = errors.New("invalid key type")
    ErrSigningFailed  = errors.New("signing operation failed")
)

// KeyType represents supported key algorithms
type KeyType int

const (
    KeyTypeEd25519 KeyType = iota
    KeyTypeElgamal
    // Add other key types as needed
)

// SecretKeyProvider extends the basic crypto interfaces
type SecretKeyProvider interface {
    crypto.Signer
    Type() KeyType
    Raw() []byte
}

// Ed25519SecretKey provides a type-safe wrapper
type Ed25519SecretKey struct {
    key ed25519.PrivateKey
}

func NewEd25519SecretKey(key ed25519.PrivateKey) (*Ed25519SecretKey, error) {
    if len(key) != ed25519.PrivateKeySize {
        return nil, fmt.Errorf("%w: invalid Ed25519 key size", ErrInvalidKeyType)
    }
    return &Ed25519SecretKey{key: key}, nil
}

func (k *Ed25519SecretKey) Type() KeyType {
    return KeyTypeEd25519
}

func (k *Ed25519SecretKey) Raw() []byte {
    return k.key
}

func (k *Ed25519SecretKey) Public() crypto.PublicKey {
    return k.key.Public()
}

func (k *Ed25519SecretKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    if k == nil || len(k.key) != ed25519.PrivateKeySize {
        return nil, fmt.Errorf("%w: invalid key state", ErrInvalidKeyType)
    }
    return k.key.Sign(rand, digest, opts)
}