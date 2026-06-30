package service

import (
	"crypto/rand"
	"testing"
)

func TestEncryptDecryptTOTPSecret(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := "JBSWY3DPEHPK3PXP"

	ciphertext, err := encryptTOTPSecret(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if ciphertext == plaintext {
		t.Error("ciphertext must not equal plaintext")
	}

	got, err := decryptTOTPSecret(key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != plaintext {
		t.Errorf("got %q, want %q", got, plaintext)
	}
}

func TestEncryptProducesUniqueCiphertexts(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	c1, _ := encryptTOTPSecret(key, "secret")
	c2, _ := encryptTOTPSecret(key, "secret")
	if c1 == c2 {
		t.Error("each encryption must produce a unique ciphertext (random nonce)")
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	ct, _ := encryptTOTPSecret(key1, "secret")
	_, err := decryptTOTPSecret(key2, ct)
	if err == nil {
		t.Error("decryption with wrong key must fail")
	}
}

func TestDecryptCorruptedDataFails(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	_, err := decryptTOTPSecret(key, "bm90YmFzZTY0ISEh")
	if err == nil {
		t.Error("decryption of corrupted data must fail")
	}
}
