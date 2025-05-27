package i2pkeys

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// LoadKeysIncompat loads keys from a non-standard format
func LoadKeysIncompat(r io.Reader) (I2PKeys, error) {
	log.Debug("Loading keys from reader")
	var buff bytes.Buffer
	_, err := io.Copy(&buff, r)
	if err != nil {
		log.WithError(err).Error("Error copying from reader, did not load keys")
		return I2PKeys{}, fmt.Errorf("error copying from reader: %w", err)
	}

	parts := strings.Split(buff.String(), "\n")
	if len(parts) < 2 {
		err := errors.New("invalid key format: not enough data")
		log.WithError(err).Error("Error parsing keys")
		return I2PKeys{}, err
	}

	k := I2PKeys{I2PAddr(parts[0]), parts[1]}
	log.WithField("keys", k).Debug("Loaded keys")
	return k, nil
}

// load keys from non-standard format by specifying a text file.
// If the file does not exist, generate keys, otherwise, fail
// closed.
func LoadKeys(r string) (I2PKeys, error) {
	log.WithField("filename", r).Debug("Loading keys from file")
	exists, err := fileExists(r)
	if err != nil {
		log.WithError(err).Error("Error checking if file exists")
		return I2PKeys{}, err
	}
	if !exists {
		// File doesn't exist so we'll generate new keys
		log.WithError(err).Debug("File does not exist, attempting to generate new keys")
		k, err := NewDestination()
		if err != nil {
			log.WithError(err).Error("Error generating new keys")
			return I2PKeys{}, err
		}
		// Save the new keys to the file
		err = StoreKeys(*k, r)
		if err != nil {
			log.WithError(err).Error("Error saving new keys to file")
			return I2PKeys{}, err
		}
		return *k, nil
	}
	fi, err := os.Open(r)
	if err != nil {
		log.WithError(err).WithField("filename", r).Error("Error opening file")
		return I2PKeys{}, fmt.Errorf("error opening file: %w", err)
	}
	defer fi.Close()
	log.WithField("filename", r).Debug("File opened successfully")
	return LoadKeysIncompat(fi)
}
