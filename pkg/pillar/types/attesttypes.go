// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"
)

//AttestNonce carries nonce published by requester
type AttestNonce struct {
	nonce     []byte
	requester string
}

//Key returns nonce content, which is the key as well
func (nonce AttestNonce) Key() string {
	return nonce.requester
}

//SigAlg denotes the Signature algorithm in use e.g. ECDSA, RSASSA
type SigAlg uint8

//CertType carries the certificate use case e.g. ek, ecdh_exchange etc
type CertType uint8

//CertHashType carries the hash algo used for compute the short hash
type CertHashType uint8

//PCRExtendHashType carries the hash algo used in PCR Extend operation
type PCRExtendHashType uint8

//Various certificate types published by tpmmgr
const (
	SigAlgNone SigAlg = iota + 0
	EcdsaSha256
	RsaRsassa256
)

//PCR Extend Hash Algorithm used
const (
	PCRExtendHashAlgoNone PCRExtendHashType = iota + 0
	PCRExtendHashAlgoSha1
	PCRExtendHashAlgoSha256
)

//Needs to match api/proto/attest/attest.proto:ZEveCertType
//Various types defined under CertType
const (
	CertTypeNone CertType = iota + 0 //Default
	CertTypeOnboarding
	CertTypeRestrictSigning
	CertTypeEk
	CertTypeEcdhXchange
)

//PCRValue contains value of single PCR
type PCRValue struct {
	index  uint8
	algo   PCRExtendHashType
	digest []byte
}

//AttestQuote contains attestation quote
type AttestQuote struct {
	nonce     []byte     //Nonce provided by the requester
	sigType   SigAlg     //The signature algorithm used
	signature []byte     //ASN1 encoded signature
	quote     []byte     //the quote structure
	pcrs      []PCRValue //pcr values
}

//Key uniquely identifies an AttestQuote object
func (quote AttestQuote) Key() []byte {
	return quote.nonce
}

//Needs to match api/proto/attest/attest.proto:ZEveCertHashType
//Various CertHashType fields
const (
	CertHashTypeNone          = iota + 0
	CertHashTypeSha256First16 = 1 // hash with sha256, the 1st 16 bytes of result in 'certHash'
)

// EdgeNodeCert : contains additional device certificates such as
// - attest signing certificate published by tpmmgr
// - ECDH certificate published by tpmmgr
type EdgeNodeCert struct {
	HashAlgo CertHashType //hash method used to arrive at certHash
	CertID   []byte       //Hash of the cert, computed using hashAlgo
	CertType CertType     //type of the certificate
	Cert     []byte       //PEM encoded
	IsTpm    bool         //TPM generated or, not
}

//Key uniquely identifies the certificate
func (cert EdgeNodeCert) Key() string {
	return hex.EncodeToString(cert.CertID)
}
