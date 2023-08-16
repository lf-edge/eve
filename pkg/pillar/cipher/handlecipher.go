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
	"os"

	zcommon "github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// DecryptCipherContext has subscriptions to controller certs
// and cipher contexts for doing decryption
type DecryptCipherContext struct {
	Log               *base.LogObject
	AgentName         string
	AgentMetrics      *AgentMetrics
	SubControllerCert pubsub.Subscription
	SubEdgeNodeCert   pubsub.Subscription
}

// look up controller cert
func lookupControllerCert(ctx *DecryptCipherContext, key string) *types.ControllerCert {
	ctx.Log.Functionf("lookupControllerCert(%s)\n", key)
	sub := ctx.SubControllerCert
	item, err := sub.Get(key)
	if err != nil {
		ctx.Log.Errorf("lookupControllerCert(%s) not found\n", key)
		return nil
	}
	status := item.(types.ControllerCert)
	ctx.Log.Functionf("lookupControllerCert(%s) Done\n", key)
	return &status
}

// get embedded cipher context
func getCipherContext(ctx *DecryptCipherContext, cipherBlock types.CipherBlockStatus) *types.CipherContext {
	ctx.Log.Functionf("getCipherContext(%s)", cipherBlock.CipherBlockID)
	if cipherBlock.CipherContext != nil {
		ctx.Log.Functionf("getCipherContext(%s) use embedded CipherContext", cipherBlock.CipherBlockID)
		return cipherBlock.CipherContext
	}
	ctx.Log.Errorf("getCipherContext(%s) embedded CipherContext not found", cipherBlock.CipherBlockID)
	return nil
}

// look up edge node cert
func lookupEdgeNodeCert(ctx *DecryptCipherContext, key string) *types.EdgeNodeCert {
	ctx.Log.Functionf("lookupEdgeNodeCert(%s)\n", key)
	sub := ctx.SubEdgeNodeCert
	item, err := sub.Get(key)
	if err != nil {
		ctx.Log.Errorf("lookupEdgeNodeCert(%s) not found\n", key)
		return nil
	}
	status := item.(types.EdgeNodeCert)
	ctx.Log.Functionf("lookupEdgeNodeCert(%s) Done\n", key)
	return &status
}

func getDeviceCert(ctx *DecryptCipherContext,
	cipherBlock types.CipherBlockStatus) ([]byte, error) {

	ctx.Log.Functionf("getDeviceCert for %s\n", cipherBlock.CipherBlockID)
	cipherContext := getCipherContext(ctx, cipherBlock)
	if cipherContext == nil {
		errStr := fmt.Sprintf("cipher context %s not found\n",
			cipherBlock.CipherContextID)
		ctx.Log.Error(errStr)
		return []byte{}, errors.New(errStr)
	}
	// TBD:XXX as of now, only one
	certBytes, err := os.ReadFile(types.DeviceCertName)
	if err != nil {
		errStr := fmt.Sprintf("getDeviceCert failed while reading device certificate: %v",
			err)
		ctx.Log.Error(errStr)
		return []byte{}, errors.New(errStr)
	}
	if computeAndMatchHash(certBytes, cipherContext.DeviceCertHash,
		cipherContext.HashScheme) {
		ctx.Log.Functionf("getDeviceCert for %s Done\n", cipherBlock.CipherBlockID)
		return certBytes, nil
	}
	errStr := fmt.Sprintf("getDeviceCert for %s not found\n",
		cipherBlock.CipherBlockID)
	ctx.Log.Error(errStr)
	return []byte{}, errors.New(errStr)
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
	cipherContext := getCipherContext(ctx, cipherBlock)
	if cipherContext == nil {
		errStr := fmt.Sprintf("cipher context %s not found\n",
			cipherBlock.CipherContextID)
		ctx.Log.Error(errStr)
		return []byte{}, errors.New(errStr)
	}
	switch cipherContext.KeyExchangeScheme {
	case zcommon.KeyExchangeScheme_KEA_NONE:
		return []byte{}, errors.New("No Key Exchange Scheme")

	case zcommon.KeyExchangeScheme_KEA_ECDH:
		clearData, err := decryptCipherBlockWithECDH(ctx, cipherContext, cipherBlock)
		if err != nil {
			return []byte{}, err
		}
		if ret := validateDataHash(clearData, cipherBlock.ClearTextHash); !ret {
			return []byte{}, errors.New("Data Validation Failed")
		}
		return clearData, nil
	}
	return []byte{}, errors.New("Unsupported Cipher Key Exchange Scheme")
}

func decryptCipherBlockWithECDH(ctx *DecryptCipherContext,
	cipherContext *types.CipherContext, cipherBlock types.CipherBlockStatus) ([]byte, error) {
	cert, err := getControllerCertEcdhKey(ctx, cipherContext.ControllerCertKey())
	if err != nil {
		ctx.Log.Errorf("ECDH Certificate Key Information get fail")
		return []byte{}, err
	}
	edgeNodeCert := lookupEdgeNodeCert(ctx, cipherContext.EdgeNodeCertKey())
	if edgeNodeCert == nil {
		errStr := fmt.Sprint("Edge Node Certificate get fail")
		ctx.Log.Errorf(errStr)
		return []byte{}, errors.New(errStr)
	}
	switch cipherContext.EncryptionScheme {
	case zcommon.EncryptionScheme_SA_NONE:
		return []byte{}, errors.New("No Encryption")

	case zcommon.EncryptionScheme_SA_AES_256_CFB:
		if len(cipherBlock.InitialValue) == 0 {
			return []byte{}, errors.New("Invalid Initial value")
		}
		clearData := make([]byte, len(cipherBlock.CipherData))
		err = etpm.DecryptSecretWithEcdhKey(ctx.Log, cert.X, cert.Y,
			edgeNodeCert, cipherBlock.InitialValue, cipherBlock.CipherData, clearData)
		if err != nil {
			errStr := fmt.Sprintf("Decryption failed with error %v\n", err)
			ctx.Log.Error(errStr)
			return []byte{}, errors.New(errStr)
		}
		return clearData, nil
	}
	return []byte{}, errors.New("Unsupported Encryption protocol")
}

func getControllerCertEcdhKey(ctx *DecryptCipherContext, key string) (*ecdsa.PublicKey, error) {
	config := lookupControllerCert(ctx, key)
	if config == nil {
		errStr := fmt.Sprintf("Controller Certificate get fail")
		ctx.Log.Error(errStr)
		return nil, errors.New(errStr)
	}
	certBlock := config.Cert
	certs := []*x509.Certificate{}
	for b, rest := pem.Decode(certBlock); b != nil; b, rest = pem.Decode(rest) {
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
		ecdhPubKey := certs[0].PublicKey.(*ecdsa.PublicKey)
		return ecdhPubKey, nil
	default:
		return nil, errors.New("Not ECDSA Key")
	}
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
