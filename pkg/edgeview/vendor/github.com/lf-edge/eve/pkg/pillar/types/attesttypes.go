// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// AttestNonce carries nonce published by requester
type AttestNonce struct {
	Nonce     []byte
	Requester string
}

// Key returns nonce content, which is the key as well
func (nonce AttestNonce) Key() string {
	return hex.EncodeToString(nonce.Nonce)
}

// LogCreate :
func (nonce AttestNonce) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.AttestNonceLogType, "",
		nilUUID, nonce.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Attest nonce create")
}

// LogModify :
func (nonce AttestNonce) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.AttestNonceLogType, "",
		nilUUID, nonce.LogKey())

	oldNonce, ok := old.(AttestNonce)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of AttestNonce type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldNonce, nonce)).
		Noticef("Attest nonce modify")
}

// LogDelete :
func (nonce AttestNonce) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.AttestNonceLogType, "",
		nilUUID, nonce.LogKey())
	logObject.Noticef("Attest nonce delete")

	base.DeleteLogObject(logBase, nonce.LogKey())
}

// LogKey :
func (nonce AttestNonce) LogKey() string {
	return string(base.AttestNonceLogType) + "-" + nonce.Key()
}

// SigAlg denotes the Signature algorithm in use e.g. ECDSA, RSASSA
type SigAlg uint8

// CertType carries the certificate use case e.g. ek, ecdh_exchange etc
type CertType uint8

// CertHashType carries the hash algo used for compute the short hash
type CertHashType uint8

// PCRExtendHashType carries the hash algo used in PCR Extend operation
type PCRExtendHashType uint8

// CertMetaDataType is used for telling which type of MetaData is populated
type CertMetaDataType uint8

// Different values for CertMetaDataType
const (
	CertMetaDataTypeNone CertMetaDataType = iota + 0
	CertMetaDataTypeTpm2Public
)

// CertMetaData stores a pair of type and value for a MetaData
type CertMetaData struct {
	Type CertMetaDataType
	Data []byte
}

// Various certificate types published by tpmmgr
const (
	SigAlgNone SigAlg = iota + 0
	EcdsaSha256
	RsaRsassa256
)

// PCR Extend Hash Algorithm used
const (
	PCRExtendHashAlgoNone PCRExtendHashType = iota + 0
	PCRExtendHashAlgoSha1
	PCRExtendHashAlgoSha256
)

// Needs to match api/proto/attest/attest.proto:ZEveCertType
// Various types defined under CertType
const (
	CertTypeNone CertType = iota + 0 //Default
	CertTypeOnboarding
	CertTypeRestrictSigning
	CertTypeEk
	CertTypeEcdhXchange
)

// PCRValue contains value of single PCR
type PCRValue struct {
	Index  uint8
	Algo   PCRExtendHashType
	Digest []byte
}

// AttestQuote contains attestation quote
type AttestQuote struct {
	Nonce     []byte     //Nonce provided by the requester
	SigType   SigAlg     //The signature algorithm used
	Signature []byte     //ASN1 encoded signature
	Quote     []byte     //the quote structure
	PCRs      []PCRValue //pcr values
}

// Key uniquely identifies an AttestQuote object
func (quote AttestQuote) Key() string {
	return hex.EncodeToString(quote.Nonce)
}

// LogCreate :
func (quote AttestQuote) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.AttestQuoteLogType, "",
		nilUUID, quote.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Attest quote create")
}

// LogModify :
func (quote AttestQuote) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.AttestQuoteLogType, "",
		nilUUID, quote.LogKey())

	oldQuote, ok := old.(AttestQuote)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of AttestQuote type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldQuote, quote)).
		Noticef("Attest quote modify")
}

// LogDelete :
func (quote AttestQuote) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.AttestQuoteLogType, "",
		nilUUID, quote.LogKey())
	logObject.Noticef("Attest quote delete")

	base.DeleteLogObject(logBase, quote.LogKey())
}

// LogKey :
func (quote AttestQuote) LogKey() string {
	return string(base.AttestQuoteLogType) + "-" + quote.Key()
}

// Needs to match api/proto/attest/attest.proto:ZEveCertHashType
// Various CertHashType fields
const (
	CertHashTypeNone          = iota + 0
	CertHashTypeSha256First16 = 1 // hash with sha256, the 1st 16 bytes of result in 'certHash'
)

// EdgeNodeCert : contains additional device certificates such as
// - attest signing certificate published by tpmmgr
// - ECDH certificate published by tpmmgr
type EdgeNodeCert struct {
	HashAlgo      CertHashType   //hash method used to arrive at certHash
	CertID        []byte         //Hash of the cert, computed using hashAlgo
	CertType      CertType       //type of the certificate
	Cert          []byte         //PEM encoded
	IsTpm         bool           //TPM generated or, not
	MetaDataItems []CertMetaData //Meta data items associated with this cert(can be empty)
}

// Key uniquely identifies the certificate
func (cert EdgeNodeCert) Key() string {
	return hex.EncodeToString(cert.CertID)
}

// LogCreate :
func (cert EdgeNodeCert) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.EdgeNodeCertLogType, "",
		nilUUID, cert.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Edge node cert create")
}

// LogModify :
func (cert EdgeNodeCert) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.EdgeNodeCertLogType, "",
		nilUUID, cert.LogKey())

	oldCert, ok := old.(EdgeNodeCert)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of EdgeNodeCert type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldCert, cert)).
		Noticef("Edge node cert modify")
}

// LogDelete :
func (cert EdgeNodeCert) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.EdgeNodeCertLogType, "",
		nilUUID, cert.LogKey())
	logObject.Noticef("Edge node cert delete")

	base.DeleteLogObject(logBase, cert.LogKey())
}

// LogKey :
func (cert EdgeNodeCert) LogKey() string {
	return string(base.EdgeNodeCertLogType) + "-" + cert.Key()
}
