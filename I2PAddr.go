package i2pkeys

import (
	"crypto/sha256"
	"errors"
	"strings"
)

// I2PAddr represents an I2P destination, almost equivalent to an IP address.
// This is the humongously huge base64 representation of such an address, which
// really is just a pair of public keys and also maybe a certificate. (I2P hides
// the details of exactly what it is. Read the I2P specifications for more info.)
type I2PAddr string

// Returns the base64 representation of the I2PAddr
func (a I2PAddr) Base64() string {
	return string(a)
}

// Returns the I2P destination (base32-encoded)
func (a I2PAddr) String() string {
	if StringIsBase64 {
		return a.Base64()
	}
	return string(a.Base32())
}

// Returns "I2P"
func (a I2PAddr) Network() string {
	return "I2P"
}

// Creates a new I2P address from a base64-encoded string. Checks if the address
// addr is in correct format. (If you know for sure it is, use I2PAddr(addr).)
func NewI2PAddrFromString(addr string) (I2PAddr, error) {
	log.WithField("addr", addr).Debug("Creating new I2PAddr from string")
	if strings.HasSuffix(addr, ".i2p") {
		if strings.HasSuffix(addr, ".b32.i2p") {
			// do a lookup of the b32
			log.Warn("Cannot convert .b32.i2p to full destination")
			return I2PAddr(""), errors.New("cannot convert .b32.i2p to full destination")
		}
		// strip off .i2p if it's there
		addr = addr[:len(addr)-4]
	}
	addr = strings.Trim(addr, "\t\n\r\f ")
	// very basic check
	if len(addr) > 4096 || len(addr) < 516 {
		log.Error("Invalid I2P address length")
		return I2PAddr(""), errors.New(addr + " is not an I2P address")
	}
	buf := make([]byte, i2pB64enc.DecodedLen(len(addr)))
	if _, err := i2pB64enc.Decode(buf, []byte(addr)); err != nil {
		log.Error("Address is not base64-encoded")
		return I2PAddr(""), errors.New("Address is not base64-encoded")
	}
	log.Debug("Successfully created I2PAddr from string")
	return I2PAddr(addr), nil
}

func FiveHundredAs() I2PAddr {
	log.Debug("Generating I2PAddr with 500 'A's")
	s := ""
	for x := 0; x < 517; x++ {
		s += "A"
	}
	r, _ := NewI2PAddrFromString(s)
	return r
}

// Creates a new I2P address from a byte array. The inverse of ToBytes().
func NewI2PAddrFromBytes(addr []byte) (I2PAddr, error) {
	log.Debug("Creating I2PAddr from bytes")
	if len(addr) > 4096 || len(addr) < 384 {
		log.Error("Invalid I2P address length")
		return I2PAddr(""), errors.New("Not an I2P address")
	}
	buf := make([]byte, i2pB64enc.EncodedLen(len(addr)))
	i2pB64enc.Encode(buf, addr)
	return I2PAddr(string(buf)), nil
}

// Turns an I2P address to a byte array. The inverse of NewI2PAddrFromBytes().
func (addr I2PAddr) ToBytes() ([]byte, error) {
	return i2pB64enc.DecodeString(string(addr))
}

func (addr I2PAddr) Bytes() []byte {
	b, _ := addr.ToBytes()
	return b
}

// Returns the *.b32.i2p address of the I2P address. It is supposed to be a
// somewhat human-manageable 64 character long pseudo-domain name equivalent of
// the 516+ characters long default base64-address (the I2PAddr format). It is
// not possible to turn the base32-address back into a usable I2PAddr without
// performing a Lookup(). Lookup only works if you are using the I2PAddr from
// which the b32 address was generated.
func (addr I2PAddr) Base32() (str string) {
	return addr.DestHash().String()
}

func (addr I2PAddr) DestHash() (h I2PDestHash) {
	hash := sha256.New()
	b, _ := addr.ToBytes()
	hash.Write(b)
	digest := hash.Sum(nil)
	copy(h[:], digest)
	return
}

// Makes any string into a *.b32.i2p human-readable I2P address. This makes no
// sense, unless "anything" is an I2P destination of some sort.
func Base32(anything string) string {
	return I2PAddr(anything).Base32()
}
