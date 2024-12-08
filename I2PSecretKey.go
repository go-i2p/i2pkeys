// i2p_secret_key.go
package i2pkeys

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// SecretKey returns a type-safe secret key implementation
func (k I2PKeys) SecretKey() (SecretKeyProvider, error) {
	rawKey := k.Private()
	if len(rawKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: expected Ed25519 key", ErrInvalidKeyType)
	}

	return NewEd25519SecretKey(ed25519.PrivateKey(rawKey))
}

// PrivateKey returns the crypto.PrivateKey interface implementation
func (k I2PKeys) PrivateKey() (crypto.PrivateKey, error) {
	sk, err := k.SecretKey()
	if err != nil {
		return nil, fmt.Errorf("getting secret key: %w", err)
	}
	return sk, nil
}

// Ed25519PrivateKey safely converts to ed25519.PrivateKey
func (k I2PKeys) Ed25519PrivateKey() (ed25519.PrivateKey, error) {
	sk, err := k.SecretKey()
	if err != nil {
		return nil, err
	}

	if sk.Type() != KeyTypeEd25519 {
		return nil, fmt.Errorf("%w: not an Ed25519 key", ErrInvalidKeyType)
	}

	return ed25519.PrivateKey(sk.Raw()), nil
}

// Sign implements crypto.Signer
func (k I2PKeys) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sk, err := k.SecretKey()
	if err != nil {
		return nil, fmt.Errorf("getting secret key: %w", err)
	}

	sig, err := sk.Sign(rand, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}

	return sig, nil
}

// HostnameEntry creates a signed hostname entry
func (k I2PKeys) HostnameEntry(hostname string, opts crypto.SignerOpts) (string, error) {
	if hostname == "" {
		return "", errors.New("empty hostname")
	}

	sig, err := k.Sign(rand.Reader, []byte(hostname), opts)
	if err != nil {
		return "", fmt.Errorf("signing hostname: %w", err)
	}

	return string(sig), nil
}
