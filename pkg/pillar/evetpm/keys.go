// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetpm

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"

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
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	var keyDERBlock *pem.Block
	keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
	if keyDERBlock == nil {
		return nil, errors.New("No valid private key found")
	}
	//Expect it to be "EC PRIVATE KEY" format
	privateKey, err := x509.ParseECPrivateKey(keyDERBlock.Bytes)
	if err == nil {
		return privateKey, nil
	}
	//Try "PRIVATE KEY" format, as a fallback
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes)
	if err == nil {
		var pkey *ecdsa.PrivateKey
		var ok bool
		if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
			return nil, errors.New("Private key is not ecdsa type")
		}
		return pkey, nil
	}
	return nil, err
}
