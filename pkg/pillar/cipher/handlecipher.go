// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cipher

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	zconfig "github.com/lf-edge/eve/api/go/config"
	zcommon "github.com/lf-edge/eve/api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/cmd/tpmmgr"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// DecryptCipherContext has subscriptions to controller certs
// and cipher contexts for doing decryption
type DecryptCipherContext struct {
	SubCipherContextStatus pubsub.Subscription
	SubEveNodeCertConfig   pubsub.Subscription
}

// look up cipher context
func lookupCipherContextStatus(ctx *DecryptCipherContext,
	key string) *types.CipherContextStatus {
	log.Infof("lookupCipherContextStatus(%s)\n", key)
	sub := ctx.SubCipherContextStatus
	item, err := sub.Get(key)
	if err != nil {
		log.Errorf("lookupCipherContextStatus(%s) not found\n", key)
		return nil
	}
	status := item.(types.CipherContextStatus)
	log.Infof("lookupCipherContextStatus(%s) done\n", key)
	return &status
}

func getControllerCert(ctx *DecryptCipherContext,
	status *types.CipherContextStatus) ([]byte, error) {

	log.Infof("getControllerCert for %s\n", status.ContextID)
	if status.HasError() {
		errStr := fmt.Sprintf("controller cert has following error: %v",
			status.Error)
		log.Error(errStr)
		return []byte{}, errors.New(errStr)
	}
	if len(status.ControllerCert) == 0 {
		errStr := fmt.Sprintf("controller cert not found")
		log.Error(errStr)
		return []byte{}, errors.New(errStr)
	}
	log.Infof("getControllerCert for %s Done\n", status.ContextID)
	return status.ControllerCert, nil
}

// hash function
func computeAndMatchHash(cert []byte, suppliedHash []byte,
	hashScheme zcommon.HashAlgorithm) bool {

	switch hashScheme {
	case zcommon.HashAlgorithm_HASH_ALGORITHM_INVALID:
		return false

	case zcommon.HashAlgorithm_HASH_ALGORITHM_SHA256_16BYTES:
		h := sha256.New()
		h.Write(cert)
		computedHash := h.Sum(nil)
		return bytes.Equal(suppliedHash, computedHash[:16])

	case zcommon.HashAlgorithm_HASH_ALGORITHM_SHA256_32BYTES:
		h := sha256.New()
		h.Write(cert)
		computedHash := h.Sum(nil)
		return bytes.Equal(suppliedHash, computedHash)
	}
	return false
}

// DecryptCipherBlock : Decryption API, for encrypted object information received from controller
func DecryptCipherBlock(ctx *DecryptCipherContext,
	cipherBlock types.CipherBlockStatus) ([]byte, error) {
	if len(cipherBlock.CipherData) == 0 {
		return []byte{}, errors.New("Invalid Cipher Payload")
	}
	cipherContext := lookupCipherContextStatus(ctx, cipherBlock.CipherContextID)
	if cipherContext == nil {
		errStr := fmt.Sprintf("cipher context %s not found\n",
			cipherBlock.CipherContextID)
		log.Error(errStr)
		return []byte{}, errors.New(errStr)
	}
	switch cipherContext.KeyExchangeScheme {
	case zconfig.KeyExchangeScheme_KEA_NONE:
		return []byte{}, errors.New("No Key Exchange Scheme")

	case zconfig.KeyExchangeScheme_KEA_ECDH:
		clearData, err := decryptCipherBlockWithECDH(ctx, cipherBlock)
		if err != nil {
			return []byte{}, err
		}
		if ret := validateDataHash(clearData,
			cipherBlock.ClearTextHash); !ret {
			return []byte{}, errors.New("Data Validation Failed")
		}
		return clearData, nil
	}
	return []byte{}, errors.New("Unsupported Cipher Key Exchange Scheme")
}

func decryptCipherBlockWithECDH(ctx *DecryptCipherContext,
	cipherBlock types.CipherBlockStatus) ([]byte, error) {
	status := lookupCipherContextStatus(ctx, cipherBlock.CipherContextID)
	if status == nil {
		errStr := fmt.Sprintf("cipher context %s not found\n",
			cipherBlock.CipherContextID)
		log.Error(errStr)
		return []byte{}, errors.New(errStr)
	}

	ecdhKey, err := getControllerCertEcdhKey(ctx, status)
	if err != nil {
		log.Errorf("Could not extract ECDH Certificate Information")
		return []byte{}, err
	}

	pvtKey, err := lookupEveNodeCert(ctx, status)
	if err != nil {
		log.Errorf("No  valid device Certificate")
		return []byte{}, err
	}
	switch status.EncryptionScheme {
	case zconfig.EncryptionScheme_SA_NONE:
		return []byte{}, errors.New("No Encryption")

	case zconfig.EncryptionScheme_SA_AES_256_CFB:
		if len(cipherBlock.InitialValue) == 0 {
			return []byte{}, errors.New("Invalid Initial value")
		}
		clearData := make([]byte, len(cipherBlock.CipherData))
		err = tpmmgr.DecryptSecretWithEcdhKey(ecdhKey.X, ecdhKey.Y,
			cipherBlock.InitialValue, pvtKey, cipherBlock.CipherData, clearData)
		if err != nil {
			errStr := fmt.Sprintf("Decryption failed with error %v\n", err)
			log.Error(errStr)
			return []byte{}, errors.New(errStr)
		}
		return clearData, nil
	}
	return []byte{}, errors.New("Unsupported Encryption protocol")
}

// validate the eve node certificate attributes
// and return private Key, if any
func lookupEveNodeCert(ctx *DecryptCipherContext,
	status *types.CipherContextStatus) ([]byte, error) {

	// validate the config
	if len(status.DeviceCert) == 0 ||
		status.HasError() {
		return []byte{}, errors.New("invalid certificate")
	}
	// get the private key, for software Ecdh
	sub := ctx.SubEveNodeCertConfig
	items := sub.GetAll()
	for _, item := range items {
		config := item.(types.EveNodeCertConfig)
		return config.PvtKey, nil
	}
	return []byte{}, nil
}

func getControllerCertEcdhKey(ctx *DecryptCipherContext,
	status *types.CipherContextStatus) (*ecdsa.PublicKey, error) {
	var ecdhPubKey *ecdsa.PublicKey
	block, err := getControllerCert(ctx, status)
	if err != nil {
		return nil, err
	}
	certs := []*x509.Certificate{}
	for b, rest := pem.Decode(block); b != nil; b, rest = pem.Decode(rest) {
		if b.Type == "CERTIFICATE" {
			c, e := x509.ParseCertificates(b.Bytes)
			if e != nil {
				continue
			}
			certs = append(certs, c...)
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("No X509 Certificate")
	}
	// use the first valid certificate in the chain
	switch certs[0].PublicKey.(type) {
	case *ecdsa.PublicKey:
		ecdhPubKey = certs[0].PublicKey.(*ecdsa.PublicKey)
	default:
		return ecdhPubKey, errors.New("Not ECDSA Key")
	}
	return ecdhPubKey, nil
}

// validateDataHash : returns true, on hash match
func validateDataHash(data []byte, suppliedHash []byte) bool {
	if len(data) == 0 || len(suppliedHash) == 0 {
		return false
	}
	h := sha256.New()
	h.Write(data)
	computedHash := h.Sum(nil)
	return bytes.Equal(suppliedHash, computedHash)
}
