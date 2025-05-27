package i2pkeys

import (
	"fmt"
	"io"
	"os"
)

// store keys in non standard format
func StoreKeysIncompat(k I2PKeys, w io.Writer) error {
	log.Debug("Storing keys")
	_, err := io.WriteString(w, k.Address.Base64()+"\n"+k.Both)
	if err != nil {
		log.WithError(err).Error("Error writing keys")
		return fmt.Errorf("error writing keys: %w", err)
	}
	log.WithField("keys", k).Debug("Keys stored successfully")
	return nil
}

func StoreKeys(k I2PKeys, r string) error {
	log.WithField("filename", r).Debug("Storing keys to file")
	if _, err := os.Stat(r); err != nil {
		if os.IsNotExist(err) {
			log.WithField("filename", r).Debug("File does not exist, creating new file")
			fi, err := os.Create(r)
			if err != nil {
				log.WithError(err).Error("Error creating file")
				return err
			}
			defer fi.Close()
			return StoreKeysIncompat(k, fi)
		}
		// If stat failed for reasons other than file not existing, return the error
		return err
	}
	// File exists - open in write mode to allow overwriting
	fi, err := os.OpenFile(r, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.WithError(err).Error("Error opening file")
		return err
	}
	defer fi.Close()
	return StoreKeysIncompat(k, fi)
}
