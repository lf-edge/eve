// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetpm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

//DecryptSecretWithEcdhKey recovers plaintext from the given ciphertext
//X, Y are the Z point co-ordinates in Ellyptic Curve Diffie Hellman(ECDH) Exchange
//edgeNodeCert points to the certificate that Controller used to calculate the shared secret
//iv is the Initial Value used in the ECDH exchange.
//Sha256FromECPoint() is used as KDF on the shared secret, and the derived key is used
//in aesDecrypt(), to apply the cipher on ciphertext, and recover plaintext
func DecryptSecretWithEcdhKey(X, Y *big.Int, edgeNodeCert *types.EdgeNodeCert,
	iv, ciphertext, plaintext []byte) error {
	if (X == nil) || (Y == nil) || (edgeNodeCert == nil) {
		return errors.New("DecryptSecretWithEcdhKey needs non-empty X, Y and edgeNodeCert")
	}
	decryptKey, err := getDecryptKey(X, Y, edgeNodeCert)
	if err != nil {
		log.Errorf("getDecryptKey failed: %v", err)
		return err
	}
	return aesDecrypt(plaintext, ciphertext, decryptKey[:], iv)
}

//getDecryptKey : uses the given params to construct the AES decryption Key
func getDecryptKey(X, Y *big.Int, edgeNodeCert *types.EdgeNodeCert) ([32]byte, error) {
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
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		log.Errorf("TPM open failed: %v", err)
		return [32]byte{}, err
	}
	defer rw.Close()

	p := tpm2.ECPoint{XRaw: X.Bytes(), YRaw: Y.Bytes()}

	//Recover the key, and decrypt the message
	z, err := tpm2.RecoverSharedECCSecret(rw, TpmEcdhKeyHdl, "", p)
	if err != nil {
		log.Errorf("recovering Shared Secret failed: %v", err)
		return [32]byte{}, err
	}
	decryptKey := Sha256FromECPoint(z.X(), z.Y())
	return decryptKey, nil
}

func aesDecrypt(plaintext, ciphertext, key, iv []byte) error {
	aesBlockDecrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Errorf("creating aes new cipher failed: %v", err)
		return err
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
