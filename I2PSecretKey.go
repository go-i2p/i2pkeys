package i2pkeys

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
)

// SecretKey is a private key interface
type SecretKey interface {
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
}

func (k I2PKeys) SecretKey() SecretKey {
	var pk ed25519.PrivateKey = k.Private()
	return pk
}

func (k I2PKeys) PrivateKey() crypto.PrivateKey {
	var pk ed25519.PrivateKey = k.Private()
	_, err := pk.Sign(rand.Reader, []byte("nonsense"), crypto.Hash(0))
	if err != nil {
		log.WithError(err).Warn("Error in private key signature")
		// TODO: Elgamal, P256, P384, P512, GOST? keys?
	}
	return pk
}

func (k I2PKeys) Ed25519PrivateKey() *ed25519.PrivateKey {
	return k.SecretKey().(*ed25519.PrivateKey)
}

/*
func (k I2PKeys) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	return k.SecretKey().(*ed25519.PrivateKey).Decrypt(rand, msg, opts)
}
*/

func (k I2PKeys) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return k.SecretKey().(*ed25519.PrivateKey).Sign(rand, digest, opts)
}

func (k I2PKeys) HostnameEntry(hostname string, opts crypto.SignerOpts) (string, error) {
	sig, err := k.Sign(rand.Reader, []byte(hostname), opts)
	if err != nil {
		log.WithError(err).Error("Error signing hostname")
		return "", fmt.Errorf("error signing hostname: %w", err)
	}
	return string(sig), nil
}
