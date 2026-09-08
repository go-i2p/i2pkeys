module github.com/go-i2p/i2pkeys

go 1.26.3

require github.com/go-i2p/logger v0.1.59999

require (
	github.com/sirupsen/logrus v1.10.2 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

retract (
	v0.1.59999
	v0.1.5999
	v0.1.599
)
