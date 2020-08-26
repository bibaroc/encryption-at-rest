package cryptoutils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// RandomKey reads 32 bytes from systems entropy source, and
// generates an AES-256 cipher block from that random value.
//
// It can be used to create a random recovery code.
func RandomKey() ([]byte, cipher.Block, error) {
	keyBytes := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, keyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Couldn't generate new key, %w", err)
	}
	keyAESBlock, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Couldn't generate cipher, %w", err)
	}
	return keyBytes, keyAESBlock, nil
}

// EncryptWithBlock will encrypt data using provided block cipher wrapped in Galois Counter Mode.
//
// On systems having hardware support for AES this operation can be performed in linear time.
// Potentialy this could reuse buffers to combat allocations.
func EncryptWithBlock(blk cipher.Block, data []byte) ([]byte, error) {
	aesGCM, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptWithBlock will decrypt data using provided block cipher wrapped in Galois Counter Mode.
//
// On systems having hardware support for AES this operation can be performed in linear time.
// Potentialy this could reuse buffers to combat allocations.
func DecryptWithBlock(blk cipher.Block, data []byte) ([]byte, error) {
	aesGCM, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// AESDecrypt will use a provided key to encrypt data using Galois Counter Mode.
//
// Use key of sizes 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func AESDecrypt(key, data []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return DecryptWithBlock(blk, data)
}
