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
	"github.com/lf-edge/eve/api/go/evecommon"
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

// look up cipher context status
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

func getControllerCertBytes(ctx *DecryptCipherContext,
	status *types.CipherContextStatus) ([]byte, error) {

	log.Infof("context %s, getControllerCertBytes ", status.ContextID)
	if len(status.ControllerCert) == 0 {
		errStr := fmt.Sprintf("controller cert not found")
		log.Error(errStr)
		return []byte{}, errors.New(errStr)
	}
	log.Infof("getControllerCertBytes for %s Done\n", status.ContextID)
	return status.ControllerCert, nil
}

// hash function
func computeAndMatchHash(cert []byte, suppliedHash []byte,

	hashScheme evecommon.HashAlgorithm) bool {
	h := sha256.New()
	h.Write(cert)
	computedHash := h.Sum(nil)

	switch hashScheme {
	case evecommon.HashAlgorithm_HASH_ALGORITHM_INVALID:
		return false

	case evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_16BYTES:
		return bytes.Equal(suppliedHash, computedHash[:16])

	case evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_32BYTES:
		return bytes.Equal(suppliedHash, computedHash)
	}
	return false
}

// DecryptCipherBlock : Decryption API, for encrypted object received from controller
func DecryptCipherBlock(ctx *DecryptCipherContext,
	block types.CipherBlockStatus) ([]byte, error) {
	if len(block.CipherData) == 0 {
		return []byte{}, errors.New("Invalid Cipher Payload")
	}
	status := lookupCipherContextStatus(ctx, block.CipherContextID)
	if status == nil {
		errStr := fmt.Sprintf("cipher context %s not found\n",
			block.CipherContextID)
		log.Error(errStr)
		return []byte{}, errors.New(errStr)
	}
	if status.HasError() {
		errStr := fmt.Sprintf("cipher context: %s,  has eror, %v\n",
			status.ContextID, status.Error)
		log.Error(errStr)
		return []byte{}, errors.New(errStr)
	}

	switch status.KeyExchangeScheme {
	case zconfig.KeyExchangeScheme_KEA_NONE:
		return []byte{}, errors.New("No Key Exchange Scheme")

	case zconfig.KeyExchangeScheme_KEA_ECDH:
		clearData, err := decryptCipherBlockWithECDH(ctx, status, block)
		if err != nil {
			return []byte{}, err
		}
		if ret := validateDataHash(clearData,
			block.ClearTextHash); !ret {
			return []byte{}, errors.New("Data Validation Failed")
		}
		return clearData, nil

	default:
		return []byte{}, errors.New("Unsupported Cipher Key Exchange Scheme")
	}
}

func decryptCipherBlockWithECDH(ctx *DecryptCipherContext,
	status *types.CipherContextStatus, block types.CipherBlockStatus) ([]byte, error) {

	ecdhKey, err := getControllerCertEcdhKey(ctx, status)
	if err != nil {
		log.Errorf("Could not extract ECDH Certificate Information")
		return []byte{}, err
	}

	// grt the Eve node certificate
	certType := evecommon.ZCertType_Z_CERT_TYPE_DEVICE_ECDH_EXCHANGE
	ecdhCert, err := lookupEveNodeCertificate(ctx, certType, status)
	if err != nil || ecdhCert == nil {
		log.Errorf("Invalid device Certificate")
		return []byte{}, err
	}

	switch status.EncryptionScheme {
	case zconfig.EncryptionScheme_SA_NONE:
		return []byte{}, errors.New("No Encryption")

	case zconfig.EncryptionScheme_SA_AES_256_CFB:
		if len(block.InitialValue) == 0 {
			return []byte{}, errors.New("Invalid Initial value")
		}
		clearData := make([]byte, len(block.CipherData))
		err = tpmmgr.DecryptSecretWithEcdhKey(ecdhKey.X, ecdhKey.Y,
			*ecdhCert, block.InitialValue, block.CipherData, clearData)
		if err != nil {
			errStr := fmt.Sprintf("Decryption failed with error %v\n", err)
			log.Error(errStr)
			return []byte{}, errors.New(errStr)
		}
		return clearData, nil
	}
	return []byte{}, errors.New("Unsupported Encryption protocol")
}

// look for  eve node certificate with matching hash
func lookupEveNodeCertificate(ctx *DecryptCipherContext, certType evecommon.ZCertType,
	status *types.CipherContextStatus) (*types.ZCertConfig, error) {

	sub := ctx.SubEveNodeCertConfig
	key := status.EveNodeCertKey()
	// check whether the certificate is valid
	if len(key) == 0 {
		return nil, errors.New("invalid certificate")
	}
	item, err := sub.Get(key)
	if err != nil {
		log.Errorf("lookupEveNodeCertificate(%s) not found\n", key)
		return nil, nil
	}
	config := item.(types.ZCertConfig)
	return &config, nil
}

func getControllerCertEcdhKey(ctx *DecryptCipherContext,
	status *types.CipherContextStatus) (*ecdsa.PublicKey, error) {
	var ecdhPubKey *ecdsa.PublicKey
	certBytes, err := getControllerCertBytes(ctx, status)
	if err != nil {
		return nil, err
	}
	certs := []*x509.Certificate{}
	for b, rest := pem.Decode(certBytes); b != nil; b, rest = pem.Decode(rest) {
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
