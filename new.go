package i2pkeys

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

var DefaultSAMAddress = "127.0.0.1:7656"

const (
	defaultTimeout  = 30 * time.Second
	maxResponseSize = 4096

	cmdHello      = "HELLO VERSION MIN=3.1 MAX=3.1\n"
	cmdGenerate   = "DEST GENERATE SIGNATURE_TYPE=7\n"
	responseOK    = "RESULT=OK"
	pubKeyPrefix  = "PUB="
	privKeyPrefix = "PRIV="
)

// samClient handles communication with the SAM bridge
type samClient struct {
	addr    string
	timeout time.Duration
}

// newSAMClient creates a new SAM client with optional configuration
func newSAMClient(options ...func(*samClient)) *samClient {
	client := &samClient{
		addr:    DefaultSAMAddress,
		timeout: defaultTimeout,
	}

	for _, opt := range options {
		opt(client)
	}

	return client
}

// NewDestination generates a new I2P destination using the SAM bridge.
// This is the only public function that external code should use.
func NewDestination() (*I2PKeys, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	client := newSAMClient()
	return client.generateDestination(ctx)
}

// generateDestination handles the key generation process
func (c *samClient) generateDestination(ctx context.Context) (*I2PKeys, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("connecting to SAM bridge: %w", err)
	}
	defer conn.Close()

	if err := c.handshake(ctx, conn); err != nil {
		return nil, fmt.Errorf("SAM handshake failed: %w", err)
	}

	keys, err := c.generateKeys(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("generating keys: %w", err)
	}

	return keys, nil
}

func (c *samClient) dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: c.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("dialing SAM bridge: %w", err)
	}
	return conn, nil
}

func (c *samClient) handshake(ctx context.Context, conn net.Conn) error {
	if err := c.writeCommand(conn, cmdHello); err != nil {
		return err
	}

	response, err := c.readResponse(conn)
	if err != nil {
		return err
	}

	if !strings.Contains(response, responseOK) {
		return fmt.Errorf("unexpected SAM response: %s", response)
	}

	return nil
}

func (c *samClient) generateKeys(ctx context.Context, conn net.Conn) (*I2PKeys, error) {
	if err := c.writeCommand(conn, cmdGenerate); err != nil {
		return nil, err
	}

	response, err := c.readResponse(conn)
	if err != nil {
		return nil, err
	}

	pub, priv, err := parseKeyResponse(response)
	if err != nil {
		return nil, err
	}

	return &I2PKeys{
		Address: I2PAddr(pub),
		Both:    pub + priv,
	}, nil
}

func (c *samClient) writeCommand(conn net.Conn, cmd string) error {
	_, err := conn.Write([]byte(cmd))
	if err != nil {
		return fmt.Errorf("writing command: %w", err)
	}
	return nil
}

func (c *samClient) readResponse(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}
	return strings.TrimSpace(response), nil
}

func parseKeyResponse(response string) (pub, priv string, err error) {
	parts := strings.Split(response, privKeyPrefix)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid key response format")
	}

	pubParts := strings.Split(parts[0], pubKeyPrefix)
	if len(pubParts) != 2 {
		return "", "", fmt.Errorf("invalid public key format")
	}

	pub = strings.TrimSpace(pubParts[1])
	priv = strings.TrimSpace(parts[1])

	return pub, priv, nil
}
