// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// GetDevicePrivateKey is for a device with no TPM and get the file-based
// device key
func GetDevicePrivateKey() (*ecdsa.PrivateKey, error) {
	return GetPrivateKeyFromFile(types.DeviceKeyName)
}

// device with no TPM, get the file based ECDH key
func getECDHPrivateKey() (*ecdsa.PrivateKey, error) {
	return GetPrivateKeyFromFile(EcdhKeyFile)
}

// SetECDHPrivateKeyFile is used by tpmmgr_test.go
func SetECDHPrivateKeyFile(filename string) {
	EcdhKeyFile = filename
}

// GetPrivateKeyFromFile reads a private key file on a device with no TPM
func GetPrivateKeyFromFile(keyFile string) (*ecdsa.PrivateKey, error) {
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	//Following logic is derived from steps in
	//https://golang.org/src/crypto/tls/tls.go:X509KeyPair()
	var keyDERBlock *pem.Block
	var skippedBlockTypes []string
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return nil, errors.New("Failed to find any PEM data in key input")
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return nil, errors.New("Got a certificate instead of key")
			}
			return nil, errors.New("No PEM block found with type PRIVATE KEY")
		}
		if keyDERBlock.Type == "PRIVATE KEY" ||
			strings.HasSuffix(keyDERBlock.Type, "EC PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}
	if key, err := x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes); err == nil {
		var pkey *ecdsa.PrivateKey
		var ok bool
		if pkey, ok = key.(*ecdsa.PrivateKey); !ok {
			return nil, errors.New("Private key is not ecdsa type")
		}
		return pkey, nil
	}
	if key, err := x509.ParseECPrivateKey(keyDERBlock.Bytes); err == nil {
		return key, nil
	} else {
		return nil, err
	}
}

// GetPublicKeyFromCert gets public key from a X.509 cert
func GetPublicKeyFromCert(certFile string) (crypto.PublicKey, error) {
	//read public key from ecdh certificate
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		fmt.Printf("error in reading ecdh cert file: %v", err)
		return nil, err
	}
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("error in parsing ecdh cert file: %v", err)
		return nil, err
	}
	return cert.PublicKey, nil
}
