// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package tpmmgr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// ECC ECDH Routines

//DecryptSecretWithEcdhKey recovers plaintext from given X, Y, iv and the ciphertext
func DecryptSecretWithEcdhKey(X, Y *big.Int, ecdhCert types.ZCertConfig, iv,
	ciphertext, plaintext []byte) error {
	decryptKey, err := getSymmetricKey(X, Y, ecdhCert)
	if err != nil {
		log.Errorf("getDSymmetricKey failed: %v", err)
		return err
	}
	return aesDecrypt(plaintext, ciphertext, decryptKey, iv)
}

// getAESKey : uses the ECC params to construct the AES decryption Key
func getSymmetricKey(X, Y *big.Int, ecdhCert types.ZCertConfig) ([]byte, error) {

	switch ecdhCert.Origin {
	case types.CERT_ORIGIN_EVE_NODE_SOFTWARE:
		ecdsaKey, err := getEcdsaKeySoft(ecdhCert)
		if err != nil {
			log.Errorf("getEcdsaKeySoft failed: %v", err)
			return []byte{}, err
		}
		X, Y := elliptic.P256().Params().ScalarMult(X, Y, ecdsaKey.D.Bytes())
		decryptKey := sha256FromECPoint(X, Y)
		return decryptKey[:], nil

	case types.CERT_ORIGIN_EVE_NODE_TPM:
		rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
		if err != nil {
			log.Errorf("TPM open failed: %v", err)
			return []byte{}, err
		}
		defer rw.Close()

		p := tpm2.ECPoint{X: X, Y: Y}

		//Recover the key to decrypt (EVE node Part)
		z, err := tpm2.RecoverSharedECCSecret(rw, ecdhCert.TpmHandle, "", p)
		if err != nil {
			log.Errorf("recovering Shared Secret failed: %v", err)
			return []byte{}, err
		}
		decryptKey := sha256FromECPoint(z.X, z.Y)
		return decryptKey[:], nil

	default:
		errStr := fmt.Sprintf("invalid origin")
		log.Errorf(errStr)
		return []byte{}, errors.New(errStr)
	}
}

// get the key from soft Ecdh key
func getEcdsaKeySoft(ecdhCert types.ZCertConfig) (*ecdsa.PrivateKey, error) {
	keyBlock := ecdhCert.PvtKey
	if len(keyBlock) == 0 {
		errStr := fmt.Sprintf("Invalid Pvt Key")
		log.Errorln(errStr)
		return nil, errors.New(errStr)
	}
	var derBlock *pem.Block
	derBlock, _ = pem.Decode(keyBlock)
	if derBlock == nil {
		errStr := fmt.Sprintf("No valid private key found")
		log.Errorln(errStr)
		return nil, errors.New(errStr)
	}
	privKey, err := x509.ParseECPrivateKey(derBlock.Bytes)
	if err != nil {
		errStr := fmt.Sprintf("Unable to parse private key, %v", err)
		log.Errorln(errStr)
		return nil, errors.New(errStr)
	}
	return privKey, nil
}

// AES Routines

func aesEncrypt(ciphertext, plaintext, key, iv []byte) error {
	aesBlockEncrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
	aesEncrypter.XORKeyStream(ciphertext, plaintext)
	return nil
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
