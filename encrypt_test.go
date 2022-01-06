package main

import (
	"bufio"
	"bytes"
	"strings"
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

func Test_generateTransactionKeys(t *testing.T) {
	privateKey, publicKey, err := generateTransactionKeys()
	if err != nil {
		t.Error(err)
	}
	if privateKey == nil {
		t.Error("private key was nil")
	}
	if publicKey == nil {
		t.Error("public key was nil")
	}
}

func Test_readNonce(t *testing.T) {
	inputRaw := GenerateNonce()
	okBuf := bytes.NewBuffer(bytes.Join([][]byte{encodeBase64(inputRaw), []byte{}}, []byte("\n")))

	input, err := readNonce(bufio.NewReader(okBuf))
	if err != nil {
		t.Error(err)
	}
	if len(input) != 12 {
		t.Errorf("expected nonce to have length 12 but was %d", len(input))
	}

	invalidNonceBuf := bytes.NewBuffer(bytes.Join([][]byte{encodeBase64([]byte("invalid")), []byte{}}, []byte("\n")))
	_, err = readNonce(bufio.NewReader(invalidNonceBuf))
	if !strings.Contains(err.Error(), "invalid nonce") {
		t.Errorf("expected invalid nonce error but got %s", err)
	}
}

func Test_readPublicKey(t *testing.T) {
	_, inputRaw, err := generateTransactionKeys()
	if err != nil {
		t.Error(err)
	}

	okBuf := bytes.NewBuffer(bytes.Join([][]byte{encodeBase64(inputRaw), []byte{}}, []byte("\n")))

	publicKey, err := readPublicKey(bufio.NewReader(okBuf))
	if err != nil {
		t.Error(err)
	}
	if len(publicKey) != 32 {
		t.Errorf("expected public key to have length 32 but was %x", publicKey)
	}

	invalidPublicKeyBuf := bytes.NewBuffer(bytes.Join([][]byte{encodeBase64([]byte("invalid")), []byte{}}, []byte("\n")))
	_, err = readPublicKey(bufio.NewReader(invalidPublicKeyBuf))
	if !strings.Contains(err.Error(), "invalid public key") {
		t.Errorf("expected invalid public key error but got %s", err)
	}
}
