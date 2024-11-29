package i2pkeys

import (
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
)

/*
HELLO VERSION MIN=3.1 MAX=3.1
DEST GENERATE SIGNATURE_TYPE=7
*/
func NewDestination() (*I2PKeys, error) {
	removeNewlines := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", ""), "\n", "")
	}
	//
	log.Debug("Creating new destination via SAM")
	conn, err := net.Dial("tcp", "127.0.0.1:7656")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_, err = conn.Write([]byte("HELLO VERSION MIN=3.1 MAX=3.1\n"))
	if err != nil {
		log.WithError(err).Error("Error writing to SAM bridge")
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.WithError(err).Error("Error reading from SAM bridge")
		return nil, err
	}
	if n < 1 {
		log.Error("No data received from SAM bridge")
		return nil, fmt.Errorf("no data received")
	}

	response := string(buf[:n])
	log.WithField("response", response).Debug("Received response from SAM bridge")

	if strings.Contains(string(buf[:n]), "RESULT=OK") {
		_, err = conn.Write([]byte("DEST GENERATE SIGNATURE_TYPE=7\n"))
		if err != nil {
			log.WithError(err).Error("Error writing DEST GENERATE to SAM bridge")
			return nil, err
		}
		n, err = conn.Read(buf)
		if err != nil {
			log.WithError(err).Error("Error reading destination from SAM bridge")
			return nil, err
		}
		if n < 1 {
			log.Error("No destination data received from SAM bridge")
			return nil, fmt.Errorf("no destination data received")
		}
		pub := strings.Split(strings.Split(string(buf[:n]), "PRIV=")[0], "PUB=")[1]
		_priv := strings.Split(string(buf[:n]), "PRIV=")[1]

		priv := removeNewlines(_priv) //There is an extraneous newline in the private key, so we'll remove it.

		log.WithFields(logrus.Fields{
			"_priv(pre-newline removal)": _priv,
			"priv":                       priv,
		}).Debug("Removed newline")

		log.Debug("Successfully created new destination")

		return &I2PKeys{
			Address: I2PAddr(pub),
			Both:    pub + priv,
		}, nil

	}
	log.Error("No RESULT=OK received from SAM bridge")
	return nil, fmt.Errorf("no result received")
}
