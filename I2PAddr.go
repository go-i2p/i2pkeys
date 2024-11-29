package i2pkeys

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

const (
    // Address length constraints
    MinAddressLength = 516
    MaxAddressLength = 4096
    
    // Domain suffixes
    I2PDomainSuffix    = ".i2p"
    B32DomainSuffix    = ".b32.i2p"
)

// I2PAddr represents an I2P destination, equivalent to an IP address.
// It contains a base64-encoded representation of public keys and optional certificates.
type I2PAddr string

// Base64 returns the raw base64 representation of the I2P address.
func (a I2PAddr) Base64() string {
    return string(a)
}

// String returns either the base64 or base32 representation based on configuration.
func (a I2PAddr) String() string {
    if StringIsBase64 {
        return a.Base64()
    }
    return a.Base32()
}

// Network returns the network type, always "I2P".
func (a I2PAddr) Network() string {
    return "I2P"
}

// NewI2PAddrFromString creates a new I2P address from a base64-encoded string.
// It validates the format and returns an error if the address is invalid.
func NewI2PAddrFromString(addr string) (I2PAddr, error) {
    addr = sanitizeAddress(addr)
    
    if err := validateAddressFormat(addr); err != nil {
        return I2PAddr(""), err
    }
    
    if err := validateBase64Encoding(addr); err != nil {
        return I2PAddr(""), err
    }
    
    return I2PAddr(addr), nil
}

func sanitizeAddress(addr string) string {
    // Remove domain suffix if present
    addr = strings.TrimSuffix(addr, I2PDomainSuffix)
    return strings.Trim(addr, "\t\n\r\f ")
}

func validateAddressFormat(addr string) error {
    if len(addr) > MaxAddressLength || len(addr) < MinAddressLength {
        return fmt.Errorf("invalid address length: got %d, want between %d and %d",
            len(addr), MinAddressLength, MaxAddressLength)
    }
    
    if strings.HasSuffix(addr, B32DomainSuffix) {
        return fmt.Errorf("cannot convert %s to full destination", B32DomainSuffix)
    }
    
    return nil
}

func validateBase64Encoding(addr string) error {
    buf := make([]byte, i2pB64enc.DecodedLen(len(addr)))
    if _, err := i2pB64enc.Decode(buf, []byte(addr)); err != nil {
        return fmt.Errorf("invalid base64 encoding: %w", err)
    }
    return nil
}

// NewI2PAddrFromBytes creates a new I2P address from a byte array.
func NewI2PAddrFromBytes(addr []byte) (I2PAddr, error) {
    if len(addr) > MaxAddressLength || len(addr) < MinAddressLength {
        return I2PAddr(""), fmt.Errorf("invalid address length: got %d, want between %d and %d",
            len(addr), MinAddressLength, MaxAddressLength)
    }
    
    encoded := make([]byte, i2pB64enc.EncodedLen(len(addr)))
    i2pB64enc.Encode(encoded, addr)
    return I2PAddr(encoded), nil
}

// ToBytes converts the I2P address to its raw byte representation.
func (addr I2PAddr) ToBytes() ([]byte, error) {
    decoded, err := i2pB64enc.DecodeString(string(addr))
    if err != nil {
        return nil, fmt.Errorf("decoding address: %w", err)
    }
    return decoded, nil
}

// Base32 returns the *.b32.i2p representation of the address.
func (addr I2PAddr) Base32() string {
    return addr.DestHash().String()
}

// DestHash computes the SHA-256 hash of the address.
func (addr I2PAddr) DestHash() I2PDestHash {
    var hash I2PDestHash
    h := sha256.New()
    if bytes, err := addr.ToBytes(); err == nil {
        h.Write(bytes)
        copy(hash[:], h.Sum(nil))
    }
    return hash
}