// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"

	googleuuid "github.com/google/uuid"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"google.golang.org/protobuf/proto"
)

// CryptoConfig holds cryptographic material derived from device and controller
// certificates, including certificate hashes and a shared symmetric key.
type CryptoConfig struct {
	ControllerEncCertHash []byte
	DevCertHash           []byte
	SymmetricKey          []byte
}

// NewCryptoConfig creates a CryptoConfig by hashing the device and controller
// certificates and deriving a symmetric key using ECDH between the device
// certificate's public key and the controller's private key.
func NewCryptoConfig(devECDHCert, controllerECDHCert *x509.Certificate,
	controllerECDHKey *ecdsa.PrivateKey) (*CryptoConfig, error) {
	// EVE (tpmmgr) calculates cert hash without trimming whitespace characters.
	devHash := sha256.Sum256(CertToPEM(devECDHCert))
	symmetricKey, err := calculateSymmetricKeyForEcdhAES(devECDHCert, controllerECDHKey)
	if err != nil {
		return nil, err
	}
	return &CryptoConfig{
		ControllerEncCertHash: ControllerCertHash(controllerECDHCert),
		DevCertHash:           devHash[:],
		SymmetricKey:          symmetricKey,
	}, nil
}

// ControllerCertHash returns the full SHA-256 of a controller certificate,
// computed the way Adam computes it: over the PEM encoding with surrounding
// whitespace trimmed. The full 32-byte value is what Adam puts into
// AuthContainer.SenderCertHash.
//
// Nothing on the device ever holds the full value. /certs truncates it to 16
// bytes (flagged HashAlgo=SHA256_16BYTES), which is what lands in
// types.ControllerCert.CertHash, and CreateCipherCtx likewise stores only the
// first 16 bytes in CipherContext.ControllerCertHash. Truncate before comparing
// against anything device-side.
func ControllerCertHash(cert *x509.Certificate) []byte {
	trimmed := strings.TrimSpace(string(CertToPEM(cert)))
	sum := sha256.Sum256([]byte(trimmed))
	return sum[:]
}

// CreateCipherCtx constructs a CipherContext using certificate hashes to
// derive a deterministic context identifier and encryption parameters.
func CreateCipherCtx(cfg *CryptoConfig) (*evecommon.CipherContext, error) {
	if len(cfg.DevCertHash) == 0 {
		return nil, fmt.Errorf("missing device cert hash")
	}
	// slices.Concat, not append: ControllerCertHash returns a full 32-byte array
	// slice, so appending into it would overwrite the caller's own bytes 16-31.
	hashSeed := slices.Concat(cfg.ControllerEncCertHash[:16], cfg.DevCertHash[:16])
	ctxID := googleuuid.NewSHA1(googleuuid.UUID{}, hashSeed).String()

	return &evecommon.CipherContext{
		ContextId:          ctxID,
		HashScheme:         evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_16BYTES,
		KeyExchangeScheme:  evecommon.KeyExchangeScheme_KEA_ECDH,
		EncryptionScheme:   evecommon.EncryptionScheme_SA_AES_256_CFB,
		DeviceCertHash:     cfg.DevCertHash[:16],
		ControllerCertHash: cfg.ControllerEncCertHash[:16],
	}, nil
}

// EncryptBlock serializes and encrypts an EncryptionBlock using the provided
// CryptoConfig and CipherContext.
func EncryptBlock(block *evecommon.EncryptionBlock, cfg *CryptoConfig,
	ctx *evecommon.CipherContext) (*evecommon.CipherBlock, error) {
	raw, err := proto.Marshal(block)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	iv := deriveIV(ctx.DeviceCertHash[:8], ctx.ControllerCertHash[:8])
	return createCipherBlock(raw, ctx.ContextId, cfg, iv)
}

// DecryptBlock decrypts a CipherBlock and unmarshals it into an EncryptionBlock.
func DecryptBlock(cipher *evecommon.CipherBlock,
	cfg *CryptoConfig) (*evecommon.EncryptionBlock, error) {
	raw, err := decryptCipherBlock(cipher, cfg)
	if err != nil {
		return nil, err
	}
	var block evecommon.EncryptionBlock
	if err := proto.Unmarshal(raw, &block); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &block, nil
}

// ReEncryptCipherBlock decrypts a CipherBlock using the old CryptoConfig and
// re-encrypts it in place using the new CryptoConfig and CipherContext.
// A nil block is a no-op, so callers can pass an optional field directly.
//
// This deliberately takes the block rather than its owner: not every cipher
// block in the EVE API lives in a field named CipherData (the SCEP challenge
// password and the cluster join token do not), so an owner-based interface would
// silently exclude them.
func ReEncryptCipherBlock(cipherData *evecommon.CipherBlock,
	oldCfg, newCfg *CryptoConfig, cipherCtx *evecommon.CipherContext) error {
	if cipherData == nil {
		return nil
	}
	encBlock, err := DecryptBlock(cipherData, oldCfg)
	if err != nil {
		return fmt.Errorf("unwrap: %w", err)
	}
	newCipherData, err := EncryptBlock(encBlock, newCfg, cipherCtx)
	if err != nil {
		return fmt.Errorf("wrap: %w", err)
	}

	cipherData.CipherContextId = newCipherData.CipherContextId
	cipherData.InitialValue = newCipherData.InitialValue
	cipherData.CipherData = newCipherData.CipherData
	cipherData.ClearTextSha256 = newCipherData.ClearTextSha256
	return nil
}

// deriveIV derives a 16-byte initialization vector by hashing the given inputs.
func deriveIV(a, b []byte) []byte {
	h := sha256.New()
	h.Write(a)
	h.Write(b)
	sum := h.Sum(nil)
	return sum[:16]
}

// aesEncrypt encrypts plaintext using AES-256 in CFB mode.
func aesEncrypt(iv, key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// aesDecrypt decrypts ciphertext using AES-256 in CFB mode.
func aesDecrypt(iv, key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

// createCipherBlock encrypts plaintext and wraps it into a CipherBlock,
// including integrity metadata.
func createCipherBlock(plaintext []byte, ctxID string,
	cfg *CryptoConfig, iv []byte) (*evecommon.CipherBlock, error) {
	if len(cfg.DevCertHash) == 0 {
		return nil, fmt.Errorf("missing device certificate hash")
	}
	hash := sha256.Sum256(plaintext)
	ciphertext, err := aesEncrypt(iv, cfg.SymmetricKey, plaintext)
	if err != nil {
		return nil, err
	}
	return &evecommon.CipherBlock{
		CipherContextId: ctxID,
		InitialValue:    iv,
		CipherData:      ciphertext,
		ClearTextSha256: hash[:],
	}, nil
}

// decryptCipherBlock decrypts a CipherBlock and verifies its integrity
// using the embedded SHA-256 hash.
func decryptCipherBlock(cipher *evecommon.CipherBlock, cfg *CryptoConfig) ([]byte, error) {
	if cipher == nil {
		return nil, fmt.Errorf("nil cipher block")
	}
	plaintext, err := aesDecrypt(cipher.InitialValue, cfg.SymmetricKey, cipher.CipherData)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(plaintext)
	if !generics.EqualLists(hash[:], cipher.ClearTextSha256) {
		return nil, fmt.Errorf("SHA mismatch")
	}
	return plaintext, nil
}
