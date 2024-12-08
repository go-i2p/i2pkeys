package i2pkeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSecretKeyOperations(t *testing.T) {
	// Generate test keys
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test keys: %v", err)
	}

	keys := I2PKeys{
		Address: I2PAddr(pub),
		Both:    string(priv),
	}
	t.Log(len(pub))
	t.Log(len(keys.Address))
	t.Log(pub, keys.Address)
	t.Log(len(priv))
	t.Log(len(keys.Both))
	t.Log(priv, keys.Both)

	/*t.Run("SecretKey", func(t *testing.T) {
	      sk, err := keys.SecretKey()
	      if err != nil {
	          t.Fatalf("SecretKey() error = %v", err)
	      }

	      if sk.Type() != KeyTypeEd25519 {
	          t.Errorf("Wrong key type, got %v, want %v", sk.Type(), KeyTypeEd25519)
	      }
	  })

	  t.Run("Sign", func(t *testing.T) {
	      message := []byte("test message")
	      sig, err := keys.Sign(rand.Reader, message, crypto.Hash(0))
	      if err != nil {
	          t.Fatalf("Sign() error = %v", err)
	      }

	      if !ed25519.Verify(pub, message, sig) {
	          t.Error("Signature verification failed")
	      }
	  })

	  t.Run("HostnameEntry", func(t *testing.T) {
	      hostname := "test.i2p"
	      entry, err := keys.HostnameEntry(hostname, crypto.Hash(0))
	      if err != nil {
	          t.Fatalf("HostnameEntry() error = %v", err)
	      }

	      if entry == "" {
	          t.Error("Empty hostname entry")
	      }
	  })*/
}
