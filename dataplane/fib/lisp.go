// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Code to set/get lisp header fields like key id, iid and nonce.

package fib

import (
	log "github.com/sirupsen/logrus"
)

func SetLispKeyId(hdr []byte, keyId byte) {
	if keyId > 3 {
		log.Errorf("Invalid Lisp crypto key id %v", keyId)
		return
	}
	hdr[0] = byte(hdr[0] | keyId)
}

func GetLispKeyId(hdr []byte) byte {
	keyId := byte(hdr[0] & 0x03)
	return keyId
}

func SetLispIID(hdr []byte, iid uint32) {
	iidFlagMask := byte(1 << 3)

	// Set instance id present flag
	hdr[0] = byte(hdr[0] | iidFlagMask)

	// Set instance id in lisp header
	hdr[4] = byte(iid >> 16)
	hdr[5] = byte(iid >> 8)
	hdr[6] = byte(iid)
}

func GetLispIID(hdr []byte) uint32 {
	var iid uint32 = 0

	iid = uint32(uint32(hdr[4])<<16 | uint32(hdr[5])<<8 | uint32(hdr[6]))
	return iid
}

func SetLispNonce(hdr []byte, nonce uint32) {
	// set the nonce present bit
	nonceFlagMask := byte(1 << 7)
	hdr[0] = byte(hdr[0] | nonceFlagMask)

	// set nonce into header
	hdr[1] = byte(nonce >> 16)
	hdr[2] = byte(nonce >> 8)
	hdr[3] = byte(nonce)
}

func GetLispNonce(hdr []byte) uint32 {
	var nonce uint32 = 0

	nonce = uint32(hdr[1])
	nonce = (nonce << 8) | uint32(hdr[2])
	nonce = (nonce << 8) | uint32(hdr[3])
	return nonce
}
