package i2pkeys

import (
	"crypto/sha256"
	"errors"
	"strings"
)

// an i2p destination hash, the .b32.i2p address if you will
type I2PDestHash [32]byte

// create a desthash from a string b32.i2p address
func DestHashFromString(str string) (dhash I2PDestHash, err error) {
	log.WithField("address", str).Debug("Creating desthash from string")
	if strings.HasSuffix(str, ".b32.i2p") && len(str) == 60 {
		// valid
		_, err = i2pB32enc.Decode(dhash[:], []byte(str[:52]+"===="))
		if err != nil {
			log.WithError(err).Error("Error decoding base32 address")
		}
	} else {
		// invalid
		err = errors.New("invalid desthash format")
		log.WithError(err).Error("Invalid desthash format")
	}
	return
}

// create a desthash from a []byte array
func DestHashFromBytes(str []byte) (dhash I2PDestHash, err error) {
	log.Debug("Creating DestHash from bytes")
	if len(str) == 32 {
		// valid
		//_, err = i2pB32enc.Decode(dhash[:], []byte(str[:52]+"===="))
		log.WithField("str", str).Debug("Copying str to desthash")
		copy(dhash[:], str)
	} else {
		// invalid
		err = errors.New("invalid desthash format")
		log.WithField("str", str).Error("Invalid desthash format")
	}
	return
}

// get string representation of i2p dest hash(base32 version)
func (h I2PDestHash) String() string {
	b32addr := make([]byte, 56)
	i2pB32enc.Encode(b32addr, h[:])
	return string(b32addr[:52]) + ".b32.i2p"
}

// get base64 representation of i2p dest sha256 hash(the 44-character one)
func (h I2PDestHash) Hash() string {
	hash := sha256.New()
	hash.Write(h[:])
	digest := hash.Sum(nil)
	buf := make([]byte, 44)
	i2pB64enc.Encode(buf, digest)
	return string(buf)
}

// Returns "I2P"
func (h I2PDestHash) Network() string {
	return "I2P"
}
