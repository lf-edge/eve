// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetpm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// DecryptSecretWithEcdhKey recovers plaintext from the given ciphertext
// X, Y are the Z point coordinates in Ellyptic Curve Diffie Hellman(ECDH) Exchange
// edgeNodeCert points to the certificate that Controller used to calculate the shared secret
// iv is the Initial Value used in the ECDH exchange.
// Sha256FromECPoint() is used as KDF on the shared secret, and the derived key is used
// in AESDecrypt(), to apply the cipher on ciphertext, and recover plaintext
func DecryptSecretWithEcdhKey(log *base.LogObject, X, Y *big.Int, edgeNodeCert *types.EdgeNodeCert,
	iv, ciphertext, plaintext []byte) error {
	if (X == nil) || (Y == nil) || (edgeNodeCert == nil) {
		return errors.New("DecryptSecretWithEcdhKey needs non-empty X, Y and edgeNodeCert")
	}
	decryptKey, err := getDecryptKey(log, X, Y, edgeNodeCert)
	if err != nil {
		log.Errorf("getDecryptKey failed: %v", err)
		return err
	}
	return AESDecrypt(plaintext, ciphertext, decryptKey[:], iv)
}

// getDecryptKey : uses the given params to construct the AES decryption Key
func getDecryptKey(log *base.LogObject, X, Y *big.Int, edgeNodeCert *types.EdgeNodeCert) ([32]byte, error) {
	block, _ := pem.Decode(edgeNodeCert.Cert)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return [32]byte{}, fmt.Errorf("error in parsing ecdh cert file: %v", err)
	}
	pubKey := cert.PublicKey.(*ecdsa.PublicKey)
	if !IsTpmEnabled() || !edgeNodeCert.IsTpm {
		//Either TPM is not enabled, or for some reason we are not using TPM for ECDH
		//Look for soft cert/key
		privateKey, err := getECDHPrivateKey()
		if err != nil {
			log.Errorf("getECDHPrivateKey failed: %v", err)
			return [32]byte{}, err
		}
		X, Y := elliptic.P256().Params().ScalarMult(X, Y, privateKey.D.Bytes())
		return Sha256FromECPoint(X, Y, pubKey)
	}
	return deriveSessionKey(X, Y, pubKey)
}

// AESEncrypt encrypts plaintext, and returns it in ciphertext
// by using the key and initial value given. Uses a AES CFB cipher.
func AESEncrypt(ciphertext, plaintext, key, iv []byte) error {
	aesBlockEncrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
	aesEncrypter.XORKeyStream(ciphertext, plaintext)
	return nil
}

// AESDecrypt decrypts ciphertext, and returns it in plaintext
// using the key and initial value given. Uses AES CFB cipher.
func AESDecrypt(plaintext, ciphertext, key, iv []byte) error {
	aesBlockDecrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return fmt.Errorf("creating aes new cipher failed: %v", err)
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
	aesDecrypter.XORKeyStream(plaintext, ciphertext)
	return nil
}

func ecdsakeyBytes(pubKey *ecdsa.PublicKey) (int, error) {
	curveBits := pubKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	if keyBytes%8 > 0 {
		return 0, fmt.Errorf("ecdsa pubkey size error, curveBits %v", curveBits)
	}
	return keyBytes, nil
}

// RSCombinedBytes - combine r & s into fixed length bytes
func rsCombinedBytes(rBytes, sBytes []byte, pubKey *ecdsa.PublicKey) ([]byte, error) {
	keySize, err := ecdsakeyBytes(pubKey)
	if err != nil {
		return nil, fmt.Errorf("RSCombinedBytes: ecdsa key bytes error %v", err)
	}
	rsize := len(rBytes)
	ssize := len(sBytes)
	if rsize > keySize || ssize > keySize {
		return nil, fmt.Errorf("RSCombinedBytes: error. keySize %v, rSize %v, sSize %v", keySize, rsize, ssize)
	}

	// basically the size is 32 bytes. the r and s needs to be both left padded to two 32 bytes slice
	// into a single signature buffer
	buffer := make([]byte, keySize*2)
	startPos := keySize - rsize
	copy(buffer[startPos:], rBytes)
	startPos = keySize*2 - ssize
	copy(buffer[startPos:], sBytes)
	return buffer[:], nil
}

// Sha256FromECPoint is the KDF
func Sha256FromECPoint(X, Y *big.Int, pubKey *ecdsa.PublicKey) ([32]byte, error) {
	var sha [32]byte
	bytes, err := rsCombinedBytes(X.Bytes(), Y.Bytes(), pubKey)
	if err != nil {
		return sha, fmt.Errorf("error occurred while combining bytes for ECPoints: %v", err)
	}
	return sha256.Sum256(bytes), nil
}

// deriveSessionKey derives a ECDH shared secret based on
// ECDH private key, and the provided public key
func deriveSessionKey(X, Y *big.Int, publicKey *ecdsa.PublicKey) ([32]byte, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return [32]byte{}, fmt.Errorf("TPM open failed: %v", err)
	}
	defer rw.Close()

	// ECPoint expects the point to be of specific size. Using big.Int.Bytes()
	// can lead to issues if the integers are slightly less than the max size of
	// the curve, and it can lead to missing leading zeros and errors like :
	// "error code 0x27 : point is not on the required curve"
	// FillBytes() is an option but it requires explicit size, here we use
	// EccIntToBytes to get the correctly sized byte array based on the curve.
	// If I understood the spec correctly, this issue should not occur
	// in TPMs that implement the >= v1.38 spec, specifically:
	// Trusted Platform Module Library, "Part 1: Architecture",
	// Family “2.0” Level 00 Revision 01.38, C.8 ECC Point Padding.
	p := tpm2.ECPoint{
		XRaw: EccIntToBytes(publicKey.Curve, X),
		YRaw: EccIntToBytes(publicKey.Curve, Y),
	}

	//Recover the key, and decrypt the message
	z, err := tpm2.ECDHZGen(rw, TpmEcdhKeyHdl, "", p)
	if err != nil {
		return [32]byte{}, fmt.Errorf("deriveSessionKey failed: %v", err)
	}
	return Sha256FromECPoint(z.X(), z.Y(), publicKey)
}

// deriveEncryptDecryptKey is a helper function to parse device cert
// extract the ECC points from its public key, and call deriveSessionKey
// with those ECC points
func deriveEncryptDecryptKey() ([32]byte, error) {
	publicKey, err := GetPublicKeyFromCert(types.DeviceCertName)
	if err != nil {
		return [32]byte{}, fmt.Errorf("error in GetPublicKeyFromCert: %s", err)
	}
	eccPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return [32]byte{}, fmt.Errorf("Not an ECDH compatible key: %T", publicKey)
	}

	EncryptDecryptKey, err := deriveSessionKey(eccPublicKey.X, eccPublicKey.Y, eccPublicKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("EncryptSecretWithDeviceKey failed with %v", err)
	}
	return EncryptDecryptKey, nil
}

// EncryptDecryptUsingTpm uses AES key to encrypt/decrypt a given secret
// The AES key is derived from a seed, which is further derived from device certificate
// and ECDH private key, which is protected inside the TPM. IOW, to decrypt secret successfully,
// one will need to be on the same device.
func EncryptDecryptUsingTpm(in []byte, encrypt bool) ([]byte, error) {
	key, err := deriveEncryptDecryptKey()
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	out := make([]byte, len(in))
	if encrypt {
		err = AESEncrypt(out, in, key[:], iv)
	} else {
		err = AESDecrypt(out, in, key[:], iv)
	}
	return out, err
}

// EccIntToBytes - ECC coordinates need to maintain a specific size based on the curve, so we pad the front with zeros.
// This is particularly an issue for NIST-P521 coordinates, as they are frequently missing their first byte.
// This is copied from go-tpm-tools library and is more future-proof than FillBytes().
// https://github.com/google/go-tpm-tools/blob/3e063ade7f302972d7b893ca080a75efa3db5506/server/ecc_utils.go#L11
func EccIntToBytes(curve elliptic.Curve, i *big.Int) []byte {
	bytes := i.Bytes()
	curveBytes := (curve.Params().BitSize + 7) / 8
	return append(make([]byte, curveBytes-len(bytes)), bytes...)
}
