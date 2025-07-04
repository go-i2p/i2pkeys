package i2pkeys

import (
	"crypto"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

var (
	i2pB64enc *base64.Encoding = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~")
	i2pB32enc *base32.Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")
)

// If you set this to true, Addr will return a base64 String()
var StringIsBase64 bool

// The public and private keys associated with an I2P destination. I2P hides the
// details of exactly what this is, so treat them as blobs, but generally: One
// pair of DSA keys, one pair of ElGamal keys, and sometimes (almost never) also
// a certificate. String() returns you the full content of I2PKeys and Addr()
// returns the public keys.
type I2PKeys struct {
	Address I2PAddr // only the public key
	Both    string  // both public and private keys
}

// Creates I2PKeys from an I2PAddr and a public/private keypair string (as
// generated by String().)
func NewKeys(addr I2PAddr, both string) I2PKeys {
	log.WithField("addr", addr).Debug("Creating new I2PKeys")
	return I2PKeys{addr, both}
}

// fileExists checks if a file exists and is not a directory before we
// try using it to prevent further errors.
func fileExists(filename string) (bool, error) {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		log.WithField("filename", filename).Debug("File does not exist")
		return false, nil
	} else if err != nil {
		log.WithError(err).WithField("filename", filename).Error("Error checking file existence")
		return false, fmt.Errorf("error checking file existence: %w", err)
	}
	exists := !info.IsDir()
	if exists {
		log.WithField("filename", filename).Debug("File exists")
	} else {
		log.WithField("filename", filename).Debug("File is a directory")
	}
	return !info.IsDir(), nil
}

func (k I2PKeys) Network() string {
	return k.Address.Network()
}

// Returns the public keys of the I2PKeys in Addr form
func (k I2PKeys) Addr() I2PAddr {
	return k.Address
}

// Returns the public keys of the I2PKeys.
func (k I2PKeys) Public() crypto.PublicKey {
	return k.Address
}

// Private returns the private key as a byte slice.
func (k I2PKeys) Private() []byte {
	log.Debug("Extracting private key")

	// The private key is everything after the public key in the combined string
	fullKeys := k.String()
	publicKey := k.Addr().String()

	// Find where the public key ends in the full string
	if !strings.HasPrefix(fullKeys, publicKey) {
		log.Error("Invalid key format: public key not found at start of combined keys")
		return nil
	}

	// Extract the private key portion (everything after the public key)
	privateKeyB64 := fullKeys[len(publicKey):]

	// Pre-allocate destination slice with appropriate capacity
	dest := make([]byte, i2pB64enc.DecodedLen(len(privateKeyB64)))

	n, err := i2pB64enc.Decode(dest, []byte(privateKeyB64))
	if err != nil {
		log.WithError(err).Error("Error decoding private key")
		return nil // Return nil instead of panicking
	}

	// Return only the portion that was actually decoded
	return dest[:n]
}

// Returns the keys (both public and private), in I2Ps base64 format. Use this
// when you create sessions.
func (k I2PKeys) String() string {
	return k.Both
}
