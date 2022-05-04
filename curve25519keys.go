package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"math/big"
)

const privateKeySize = 32

func generateCurve25519PrivateKey() ([]byte, error) {
	var privateKey = make([]byte, privateKeySize)

	for index := range privateKey {
		secureRandomInt, err := rand.Int(rand.Reader, big.NewInt(255))
		if err != nil {
			return nil, fmt.Errorf("failed to generate random byte: %s", err)
		}
		privateKey[index] = byte(secureRandomInt.Int64())
	}

	// As a security measure, perform bit-clamping:
	// As per recommendation of djb (https://cr.yp.to/ecdh.html) (author of Curve25519)
	// See https://loup-vaillant.fr/tutorials/cofactor for a long and in-depth explanation
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	return privateKey, nil
}

func deriveCurve25519PublicKey(privateKey []byte) ([]byte, error) {
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("error deriving public key from private key: %s", err)
	}

	return publicKey, nil
}

func computeSharedCurve25519Secret(otherPublicKey, thisPrivateKey []byte) ([]byte, error) {
	sharedKey, err := curve25519.X25519(thisPrivateKey, otherPublicKey)
	if err != nil {
		return nil, fmt.Errorf("error computing shared secret: %s", err)
	}

	sharedSecret := sha256.Sum256(sharedKey)

	return sharedSecret[:], err
}
