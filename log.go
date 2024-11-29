package i2pkeys

import (
	"github.com/go-i2p/logger"
)

var log *logger.Logger

func InitializeI2PKeysLogger() {
	logger.InitializeGoI2PLogger()
	log = logger.GetGoI2PLogger()
}

// GetI2PKeysLogger returns the initialized logger
func GetI2PKeysLogger() *logger.Logger {
	return logger.GetGoI2PLogger()
}

func init() {
	InitializeI2PKeysLogger()
}
