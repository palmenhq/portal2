package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

func GenerateNonce() []byte {
	unixTime := time.Now().UnixNano()
	buf := make([]byte, binary.MaxVarintLen64+2)
	binary.PutVarint(buf, unixTime)

	buf[10] = getRandomByte()
	buf[11] = getRandomByte()
	return buf
}

func getRandomByte() byte {
	randomByte, err := rand.Int(rand.Reader, big.NewInt(256))
	if err != nil {
		panic(err)
	}

	return randomByte.Bytes()[0]
}

func AesGcmEncrypt(plaintext, nonce, key []byte) ([]byte, error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating aes cipher while encrypting: %s", err)
	}
	aesgcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("error creating aes-gcm cipher while encrypting: %s", err)
	}

	cipherText := aesgcm.Seal(nil, nonce, plaintext, nil)

	return cipherText, err
}

func AesGcmDecrypt(ciphertext, nonce, sharedSecret []byte) ([]byte, error) {
	aesCipher, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("error creating aes cipher while decrypting: %s", err)
	}
	aesgcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("error creating aes-gcm cipher while decrypting: %s", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption error: %s", err)
	}

	return plaintext, nil
}

func generateTransactionKeys() ([]byte, []byte, error) {
	privateKey, err := generateCurve25519PrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("error generating ec private key: %s\n", err)
	}
	publicKey, err := deriveCurve25519PublicKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating ec public key: %s\n", err)
	}

	return privateKey, publicKey, nil
}

func readNonce(connReader *bufio.Reader) ([]byte, error) {
	nonce, err := readBase64Line(connReader)
	if err != nil {
		return nil, fmt.Errorf("error reading nonce: %s", err)
	}

	if len(nonce) != 12 {
		return nil, fmt.Errorf("invalid nonce, expected 12 bytes but was \"%x\"", nonce)
	}

	return nonce, nil
}

func readPublicKey(connReader *bufio.Reader) ([]byte, error) {
	publicKey, err := readBase64Line(connReader)
	if err != nil {
		return nil, fmt.Errorf("error reading public key: %s", err)
	}

	if len(publicKey) != 32 {
		return nil, fmt.Errorf("invalid public key, expected 32 bytes but was \"%x\"", publicKey)
	}

	return publicKey, nil
}
