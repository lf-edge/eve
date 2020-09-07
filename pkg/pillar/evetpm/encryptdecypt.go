// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetpm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

//DecryptSecretWithEcdhKey recovers plaintext from the given ciphertext
//X, Y are the Z point co-ordinates in Ellyptic Curve Diffie Hellman(ECDH) Exchange
//edgeNodeCert points to the certificate that Controller used to calculate the shared secret
//iv is the Initial Value used in the ECDH exchange.
//Sha256FromECPoint() is used as KDF on the shared secret, and the derived key is used
//in AESDecrypt(), to apply the cipher on ciphertext, and recover plaintext
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

//getDecryptKey : uses the given params to construct the AES decryption Key
func getDecryptKey(log *base.LogObject, X, Y *big.Int, edgeNodeCert *types.EdgeNodeCert) ([32]byte, error) {
	if !IsTpmEnabled() || !edgeNodeCert.IsTpm {
		//Either TPM is not enabled, or for some reason we are not using TPM for ECDH
		//Look for soft cert/key
		privateKey, err := getECDHPrivateKey()
		if err != nil {
			log.Errorf("getECDHPrivateKey failed: %v", err)
			return [32]byte{}, err
		}
		X, Y := elliptic.P256().Params().ScalarMult(X, Y, privateKey.D.Bytes())
		decryptKey := Sha256FromECPoint(X, Y)
		return decryptKey, nil
	}
	return deriveSessionKey(X, Y)
}

//AESEncrypt encrypts plaintext, and returns it in ciphertext
//by using the key and initial value given. Uses a AES CFB cipher.
func AESEncrypt(ciphertext, plaintext, key, iv []byte) error {
	aesBlockEncrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
	aesEncrypter.XORKeyStream(ciphertext, plaintext)
	return nil
}

//AESDecrypt decrypts ciphertext, and returns it in plaintext
//using the key and initial value given. Uses AES CFB cipher.
func AESDecrypt(plaintext, ciphertext, key, iv []byte) error {
	aesBlockDecrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return fmt.Errorf("creating aes new cipher failed: %v", err)
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
	aesDecrypter.XORKeyStream(plaintext, ciphertext)
	return nil
}

// Sha256FromECPoint is the KDF
func Sha256FromECPoint(X, Y *big.Int) [32]byte {
	var bytes = make([]byte, 0)
	bytes = append(bytes, X.Bytes()...)
	bytes = append(bytes, Y.Bytes()...)
	return sha256.Sum256(bytes)
}

//deriveSessionKey derives a ECDH shared secret based on
//ECDH private key, and the provided public key
func deriveSessionKey(X, Y *big.Int) ([32]byte, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return [32]byte{}, fmt.Errorf("TPM open failed: %v", err)
	}
	defer rw.Close()
	p := tpm2.ECPoint{XRaw: X.Bytes(), YRaw: Y.Bytes()}

	//Recover the key, and decrypt the message
	z, err := tpm2.ECDHZGen(rw, TpmEcdhKeyHdl, "", p)
	if err != nil {
		return [32]byte{}, fmt.Errorf("deriveSessionKey failed: %v", err)
	}
	decryptKey := Sha256FromECPoint(z.X(), z.Y())
	return decryptKey, nil
}

//deriveEncryptDecryptKey is a helper function to parse device cert
//extract the ECC points from its public key, and call deriveSessionKey
//with those ECC points
func deriveEncryptDecryptKey() ([32]byte, error) {
	publicKey, err := GetPublicKeyFromCert(types.DeviceCertName)
	eccPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return [32]byte{}, fmt.Errorf("Not an ECDH compatible key: %T", publicKey)
	}

	EncryptDecryptKey, err := deriveSessionKey(eccPublicKey.X, eccPublicKey.Y)
	if err != nil {
		return [32]byte{}, fmt.Errorf("EncryptSecretWithDeviceKey failed with %v", err)
	}
	return EncryptDecryptKey, nil
}

//EncryptDecryptUsingTpm uses AES key to encrypt/decrypt a given secret
//The AES key is derived from a seed, which is further derived from device certificate
//and ECDH private key, which is protected inside the TPM. IOW, to decrypt secret successfully,
//one will need to be on the same device.
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
