// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

/*
Package kdf implements the key derivation functions described in NIST SP-800-108
(see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf).

All 3 modes are implemented - counter, feedback and pipeline.
*/
package kdf

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"encoding/binary"
	"hash"
)

// PRF represents a pseudorandom function, required by the key derivation functions.
type PRF interface {
	// Len returns the length of this PRF.
	Len() uint32

	// Run computes bytes for the supplied seed and input value.
	Run(s, x []byte) []byte
}

type hmacPRF crypto.Hash

func (p hmacPRF) Len() uint32 {
	return uint32(crypto.Hash(p).Size())
}

func (p hmacPRF) Run(s, x []byte) []byte {
	h := hmac.New(func() hash.Hash { return crypto.Hash(p).New() }, s)
	h.Write(x)
	return h.Sum(nil)
}

// NewHMACPRF creates a new HMAC based PRF using the supplied digest algorithm.
func NewHMACPRF(h crypto.Hash) PRF {
	return hmacPRF(h)
}

func fixedBytes(label, context []byte, bitLength uint32) []byte {
	var res bytes.Buffer
	res.Write(label)
	res.Write([]byte{0})
	res.Write(context)
	binary.Write(&res, binary.BigEndian, bitLength)
	return res.Bytes()
}

func commonKDF(prfLen uint32, fixed []byte, bitLength uint32, fn func(uint32) []byte) []byte {
	n := (bitLength + prfLen - 1) / prfLen

	var res bytes.Buffer

	for i := uint32(1); i <= n; i++ {
		res.Write(fn(i))
	}

	return res.Bytes()[:(bitLength+7)/8]
}

func counterModeKeyInternal(prf PRF, key, fixed []byte, bitLength uint32) []byte {
	return commonKDF(prf.Len(), fixed, bitLength, func(i uint32) []byte {
		var x bytes.Buffer
		binary.Write(&x, binary.BigEndian, i)
		x.Write(fixed)
		return prf.Run(key, x.Bytes())
	})
}

// CounterModeKey derives a key of the specified length using the counter mode
// function described in NIST SP-800-108, using the supplied PRF, secret key and
// other input parameters.
func CounterModeKey(prf PRF, key, label, context []byte, bitLength uint32) []byte {
	return counterModeKeyInternal(prf, key, fixedBytes(label, context, bitLength), bitLength)
}

func feedbackModeKeyInternal(prf PRF, key, fixed, iv []byte, bitLength uint32, useCounter bool) []byte {
	k := iv

	return commonKDF(prf.Len(), fixed, bitLength, func(i uint32) []byte {
		var x bytes.Buffer
		x.Write(k)
		if useCounter {
			binary.Write(&x, binary.BigEndian, i)
		}
		x.Write(fixed)

		k = prf.Run(key, x.Bytes())
		return k
	})
}

// FeebackModeKey derives a key of the specified length using the feedback mode
// function described in NIST SP-800-108, using the supplied PRF, secret key and
// other input parameters.
//
// The useCounter argument specifies whether the iteration counter should be
// included as an input to the PRF.
func FeedbackModeKey(prf PRF, key, label, context, iv []byte, bitLength uint32, useCounter bool) []byte {
	return feedbackModeKeyInternal(prf, key, fixedBytes(label, context, bitLength), iv, bitLength, useCounter)
}

func pipelineModeKeyInternal(prf PRF, key, fixed []byte, bitLength uint32, useCounter bool) []byte {
	a := fixed

	return commonKDF(prf.Len(), fixed, bitLength, func(i uint32) []byte {
		a = prf.Run(key, a)

		var x bytes.Buffer
		x.Write(a)
		if useCounter {
			binary.Write(&x, binary.BigEndian, i)
		}
		x.Write(fixed)

		return prf.Run(key, x.Bytes())
	})
}

// PipelineModeKey derives a key of the specified length using the double-pipeline
// iteration mode function described in NIST SP-800-108, using the supplied PRF,
// secret key and other input parameters.
//
// The useCounter argument specifies whether the iteration counter should be
// included as an input to the PRF.
func PipelineModeKey(prf PRF, key, label, context []byte, bitLength uint32, useCounter bool) []byte {
	return pipelineModeKeyInternal(prf, key, fixedBytes(label, context, bitLength), bitLength, useCounter)
}
