package portal2

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func Test_generateCurve25519SecretKey(t *testing.T) {
	privateKey, err := generateCurve25519PrivateKey()
	if err != nil {
		t.Error(err)
	}

	if len(privateKey) != 32 {
		t.Errorf("expected private key to be 32 bytes but was really %d", len(privateKey))
	}

	if bytes.Equal(make([]byte, 32), privateKey) {
		t.Errorf("expected private key to not be the initiated value but was %x", privateKey)
	}
}

func Test_deriveCurve25519PublicKey_withTestVector(t *testing.T) {
	privateKey, err := hex.DecodeString("fa10936fe8e7652a9504cf0970bf46dee8c94593ebd87f35a13dd4e1f4edd1ac")
	if err != nil {
		t.Error(err)
	}
	publicKey, err := deriveCurve25519PublicKey(privateKey)
	if err != nil {
		t.Error(err)
	}

	expectedPublicKey, err := hex.DecodeString("901737441b60c4226be178a93839a192441cb3d0bf1321f9c95dd0831cebe93e")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(publicKey, expectedPublicKey) {
		t.Errorf("expected public key to be %s but was %s", hex.EncodeToString(expectedPublicKey), hex.EncodeToString(publicKey))
	}
}

func Test_deriveCurve25519PublicKey_fromGeneratedPublicKey(t *testing.T) {
	privateKey, err := generateCurve25519PrivateKey()
	if err != nil {
		t.Error(err)
	}
	publicKey, err := deriveCurve25519PublicKey(privateKey)
	if err != nil {
		t.Error(err)
	}

	if len(publicKey) != 32 {
		t.Errorf("public key to be 32 bytes but was %d", len(publicKey))
	}
}

func Test_computeSharedCurve25519Secret_withTestVector(t *testing.T) {
	privateKeyA, err := hex.DecodeString("fa10936fe8e7652a9504cf0970bf46dee8c94593ebd87f35a13dd4e1f4edd1ac")
	if err != nil {
		t.Error(err)
	}
	publicKeyA, err := deriveCurve25519PublicKey(privateKeyA)
	if err != nil {
		t.Error(err)
	}
	privateKeyB, err := hex.DecodeString("66f8df8f45f470c3a05826408de763f781c6aa5b61d0e5e040141acdd0e6e1e0")
	if err != nil {
		t.Error(err)
	}
	publicKeyB, err := deriveCurve25519PublicKey(privateKeyB)
	if err != nil {
		t.Error(err)
	}

	sharedA, err := computeSharedCurve25519Secret(publicKeyB, privateKeyA)
	if err != nil {
		t.Error(err)
	}
	sharedB, err := computeSharedCurve25519Secret(publicKeyA, privateKeyB)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(sharedA, sharedB) {
		t.Errorf("expected shared secret a %s to equal shared secret b %s", hex.EncodeToString(sharedA), hex.EncodeToString(sharedB))
	}
}
