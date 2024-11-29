package i2pkeys

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

const (
    // HashSize is the size of an I2P destination hash in bytes
    HashSize = 32
    
    // B32AddressLength is the length of a base32 address without suffix
    B32AddressLength = 52
    
    // FullB32Length is the total length of a .b32.i2p address
    FullB32Length = 60
    
    // B32Padding is the padding used for base32 encoding
    B32Padding = "===="
    
    // B32Suffix is the standard suffix for base32 I2P addresses
    B32Suffix = ".b32.i2p"
)

// I2PDestHash represents a 32-byte I2P destination hash.
// It's commonly represented as a base32-encoded address with a .b32.i2p suffix.
type I2PDestHash [HashSize]byte

// DestHashFromString creates a destination hash from a base32-encoded string.
// The input should be in the format "base32address.b32.i2p".
func DestHashFromString(addr string) (I2PDestHash, error) {
    if !isValidB32Address(addr) {
        return I2PDestHash{}, fmt.Errorf("invalid address format: %s", addr)
    }

    var hash I2PDestHash
    b32Input := addr[:B32AddressLength] + B32Padding
    
    n, err := i2pB32enc.Decode(hash[:], []byte(b32Input))
    if err != nil {
        return I2PDestHash{}, fmt.Errorf("decoding base32 address: %w", err)
    }
    
    if n != HashSize {
        return I2PDestHash{}, fmt.Errorf("decoded hash has invalid length: got %d, want %d", n, HashSize)
    }
    
    return hash, nil
}

// isValidB32Address checks if the address has the correct format and length
func isValidB32Address(addr string) bool {
    return strings.HasSuffix(addr, B32Suffix) && len(addr) == FullB32Length
}

// DestHashFromBytes creates a destination hash from a byte slice.
// The input must be exactly 32 bytes long.
func DestHashFromBytes(data []byte) (I2PDestHash, error) {
    if len(data) != HashSize {
        return I2PDestHash{}, fmt.Errorf("invalid hash length: got %d, want %d", len(data), HashSize)
    }

    var hash I2PDestHash
    copy(hash[:], data)
    return hash, nil
}

// String returns the base32-encoded representation with the .b32.i2p suffix.
func (h I2PDestHash) String() string {
    encoded := make([]byte, i2pB32enc.EncodedLen(HashSize))
    i2pB32enc.Encode(encoded, h[:])
    return string(encoded[:B32AddressLength]) + B32Suffix
}

// Hash returns the base64-encoded SHA-256 hash of the destination hash.
func (h I2PDestHash) Hash() string {
    digest := sha256.Sum256(h[:])
    encoded := make([]byte, i2pB64enc.EncodedLen(len(digest)))
    i2pB64enc.Encode(encoded, digest[:])
    return string(encoded[:44])
}

// Network returns the network type, always "I2P".
func (h I2PDestHash) Network() string {
    return "I2P"
}