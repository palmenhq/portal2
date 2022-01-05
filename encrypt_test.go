package portal2

import (
	"bytes"
	"testing"
)

func Test_GenerateNonce(t *testing.T) {
	nonce := GenerateNonce()
	if len(nonce) != 12 {
		t.Errorf("expected generated nonce to be of length 12 but was %d", nonce)
	}
}

func Test_Encryption(t *testing.T) {
	plaintext := []byte("hello, world")
	nonce := GenerateNonce()
	key := bytes.Repeat([]byte("s"), 32)

	ciphertext, err := AesGcmEncrypt(plaintext, nonce, key)
	if err != nil {
		t.Errorf("encryption error: %s", err)
	}

	decrypted, err := AesGcmDecrypt(ciphertext, nonce, key)
	if err != nil {
		t.Errorf("decryption error: %s", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("expected decrypted message to be same as original but was really %s", decrypted)
	}
}
