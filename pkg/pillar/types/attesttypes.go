// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

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

//Various certificate types published by tpmmgr
const (
	SigAlgNone SigAlg = iota + 0
	EcdsaSha256
	RsaRsassa256
)

//AttestQuote contains attestation quote
type AttestQuote struct {
	nonce     []byte //Nonce provided by the requester
	sigType   SigAlg //The signature algorithm used
	signature []byte //ASN1 encoded signature
	quote     []byte //the quote structure
}

//Key uniquely identifies an AttestQuote object
func (quote AttestQuote) Key() []byte {
	return quote.nonce
}
