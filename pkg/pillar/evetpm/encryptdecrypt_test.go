// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetpm

import (
	"bytes"
	"crypto/rand"
	"os"
	"reflect"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func TestAESGCMEncryptDecrypt(t *testing.T) {
	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "Empty plaintext",
			plaintext: []byte{},
		},
		{
			name:      "plaintext",
			plaintext: []byte("This is test message with more content to encrypt and decrypt."),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate a random 32-byte key
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("Failed to generate random key: %v", err)
			}

			// Encrypt the plaintext
			ciphertext, err := AESGCMEncrypt(tc.plaintext, key)
			if err != nil {
				t.Fatalf("AESGCMEncrypt failed: %v", err)
			}

			// Verify ciphertext format: [4 bytes nonce size][nonce][encrypted data]
			if len(ciphertext) < 4 {
				t.Fatalf("Ciphertext too short, expected at least 4 bytes, got %d", len(ciphertext))
			}

			// Decrypt the ciphertext
			decrypted, err := AESGCMDecrypt(ciphertext, key)
			if err != nil {
				t.Fatalf("AESGCMDecrypt failed: %v", err)
			}

			// Verify the decrypted plaintext matches the original
			if !bytes.Equal(decrypted, tc.plaintext) {
				t.Errorf("Decrypted plaintext does not match original.\nExpected: %v\nGot: %v",
					tc.plaintext, decrypted)
			}
		})
	}
}

func TestAESGCMDecryptInvalidInput(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	testCases := []struct {
		name       string
		ciphertext []byte
		expectErr  bool
	}{
		{
			name:       "Empty ciphertext",
			ciphertext: []byte{},
			expectErr:  true,
		},
		{
			name:       "Too short ciphertext (less than 4 bytes)",
			ciphertext: []byte{0x01, 0x02},
			expectErr:  true,
		},
		{
			name:       "Invalid nonce size (larger than available data)",
			ciphertext: []byte{0x00, 0x00, 0x01, 0x00}, // nonce size = 256, but no data follows
			expectErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := AESGCMDecrypt(tc.ciphertext, key)
			if tc.expectErr && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tc.expectErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestAESGCMDecryptWithWrongKey(t *testing.T) {
	plaintext := []byte("Secret message")
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)

	if _, err := rand.Read(key1); err != nil {
		t.Fatalf("Failed to generate key1: %v", err)
	}
	if _, err := rand.Read(key2); err != nil {
		t.Fatalf("Failed to generate key2: %v", err)
	}

	// Encrypt with key1
	ciphertext, err := AESGCMEncrypt(plaintext, key1)
	if err != nil {
		t.Fatalf("AESGCMEncrypt failed: %v", err)
	}

	// Try to decrypt with key2 (wrong key)
	_, err = AESGCMDecrypt(ciphertext, key2)
	if err == nil {
		t.Errorf("Expected decryption to fail with wrong key, but it succeeded")
	}
}

func TestAESGCMEncryptDifferentNonces(t *testing.T) {
	plaintext := []byte("Test message")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Encrypt the same plaintext multiple times
	ciphertext1, err := AESGCMEncrypt(plaintext, key)
	if err != nil {
		t.Fatalf("AESGCMEncrypt failed: %v", err)
	}

	ciphertext2, err := AESGCMEncrypt(plaintext, key)
	if err != nil {
		t.Fatalf("AESGCMEncrypt failed: %v", err)
	}

	// The ciphertexts should be different because of random nonces
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Errorf("Expected different ciphertexts with random nonces, but got identical ones")
	}

	// Both should decrypt to the same plaintext
	decrypted1, err := AESGCMDecrypt(ciphertext1, key)
	if err != nil {
		t.Fatalf("AESGCMDecrypt failed for ciphertext1: %v", err)
	}

	decrypted2, err := AESGCMDecrypt(ciphertext2, key)
	if err != nil {
		t.Fatalf("AESGCMDecrypt failed for ciphertext2: %v", err)
	}

	if !bytes.Equal(decrypted1, plaintext) {
		t.Errorf("Decrypted1 does not match plaintext")
	}

	if !bytes.Equal(decrypted2, plaintext) {
		t.Errorf("Decrypted2 does not match plaintext")
	}
}

func TestAESGCMCiphertextFormat(t *testing.T) {
	plaintext := []byte("Test")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	ciphertext, err := AESGCMEncrypt(plaintext, key)
	if err != nil {
		t.Fatalf("AESGCMEncrypt failed: %v", err)
	}

	// Check format: [4 bytes nonce size][nonce][encrypted data]
	if len(ciphertext) < 4 {
		t.Fatalf("Ciphertext too short: %d bytes", len(ciphertext))
	}

	// Extract and verify nonce size
	nonceSize := uint32(ciphertext[0])<<24 | uint32(ciphertext[1])<<16 | uint32(ciphertext[2])<<8 | uint32(ciphertext[3])

	// Standard GCM nonce size is 12 bytes
	if nonceSize != 12 {
		t.Errorf("Expected nonce size to be 12, got %d", nonceSize)
	}

	// Verify total size is at least: 4 (size) + 12 (nonce) + some encrypted data
	minExpectedSize := 4 + 12
	if len(ciphertext) < minExpectedSize {
		t.Errorf("Ciphertext size too small: expected at least %d bytes, got %d", minExpectedSize, len(ciphertext))
	}
}

func TestEncryptDecryptUsingTpm(t *testing.T) {
	testCases := []struct {
		name       string
		version    types.VaultKeyEncVersion
		plaintext  []byte
		shouldFail bool
	}{
		{
			name:      "Legacy mode with zero IV",
			version:   types.EncryptionLegacy,
			plaintext: []byte("This is the Secret Key"),
		},
		{
			name:      "AEAD mode with random nonce",
			version:   types.EncryptionAEAD,
			plaintext: []byte("This is the Secret Key"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := EncryptDecryptUsingTpm(tc.plaintext, tc.version, true)
			if err != nil {
				if !tc.shouldFail {
					t.Fatalf("Encryption failed: %v", err)
				}
				return
			}

			// Verify ciphertext is different from plaintext
			if len(tc.plaintext) > 0 && reflect.DeepEqual(tc.plaintext, ciphertext) {
				t.Fatal("Ciphertext should not equal plaintext")
			}

			// For AEAD mode, verify the ciphertext includes nonce information
			if tc.version == types.EncryptionAEAD && len(ciphertext) < 4 {
				t.Fatal("AEAD ciphertext should include nonce size prefix")
			}

			// Decrypt
			decrypted, err := EncryptDecryptUsingTpm(ciphertext, tc.version, false)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify decrypted text matches original plaintext
			if !reflect.DeepEqual(tc.plaintext, decrypted) {
				t.Fatalf("Decrypted text does not match original.\nExpected: %v\nGot: %v",
					tc.plaintext, decrypted)
			}
		})
	}
}

// TestEncryptDecryptUsingTpm_MultipleEncryptions ensures that encrypting
// the same plaintext multiple times produces different ciphertexts in AEAD mode
func TestEncryptDecryptUsingTpm_MultipleEncryptions(t *testing.T) {
	plaintext := []byte("Same plaintext encrypted multiple times")

	// Encrypt same plaintext multiple times with AEAD mode
	ciphertext1, err := EncryptDecryptUsingTpm(plaintext, types.EncryptionAEAD, true)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	ciphertext2, err := EncryptDecryptUsingTpm(plaintext, types.EncryptionAEAD, true)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Verify the two ciphertexts are different (due to random nonce)
	if reflect.DeepEqual(ciphertext1, ciphertext2) {
		t.Fatal("Multiple encryptions of same plaintext should produce different ciphertexts in AEAD mode")
	}

	// Both should decrypt to the same plaintext
	decrypted1, err := EncryptDecryptUsingTpm(ciphertext1, types.EncryptionAEAD, false)
	if err != nil {
		t.Fatalf("First decryption failed: %v", err)
	}

	decrypted2, err := EncryptDecryptUsingTpm(ciphertext2, types.EncryptionAEAD, false)
	if err != nil {
		t.Fatalf("Second decryption failed: %v", err)
	}

	if !reflect.DeepEqual(plaintext, decrypted1) || !reflect.DeepEqual(plaintext, decrypted2) {
		t.Fatal("Both ciphertexts should decrypt to the same plaintext")
	}
}

// TestEncryptDecryptUsingTpm_InvalidVersion tests error handling for unsupported versions
func TestEncryptDecryptUsingTpm_InvalidVersion(t *testing.T) {
	deviceCertPath := "/tmp/eve-tpm/device.cert.pem"
	if _, err := os.Stat(deviceCertPath); os.IsNotExist(err) {
		t.Skipf("Device certificate not found at %s, skipping test", deviceCertPath)
	}

	plaintext := []byte("Test data")
	invalidVersion := types.VaultKeyEncVersion(999)

	// Try to encrypt with invalid version
	_, err := EncryptDecryptUsingTpm(plaintext, invalidVersion, true)
	if err == nil {
		t.Fatal("Encryption with invalid version should fail")
	}
}
