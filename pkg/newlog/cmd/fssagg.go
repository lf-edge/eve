// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/hmac"
	"crypto/sha256"
)

// Notes :
// This is based on wor of Ma and Tsudik:
// Ma, Di, and Gene Tsudik. "Forward-secure sequential aggregate authentication."
// IEEE Symposium on Security and Privacy (SP'07). IEEE, 2007.
// https://eprint.iacr.org/2007/052.pdf
//
// This implementation provides forward security, content integrity, stream integrity
// and truncation detection for each batch of logs *gzipped*. This means logs not
// yet processed by the newlogd are not protected by this scheme, the risk of an
// attacker compromising the logs can be lowered by adjusting the batch size or time
// interval to create batches of logs more frequently.
//
// Current implementation lacks the batch (or tail) deletion detection, this is
// to be implemented in the next version using tpm.
//
// Pure golang implementation of FssAgg might not be entirely safe, the initial
// key, before gc collected, might hang around a bit and swapped into disk if
// the attacker puts the system under memory pressure. Bear in mid this is a highly
// unlikly scenario. Unfortunately mlocking might not possible to implement as
// the underlying golang crypto calls copy data around into not locked memory.

// h must be a collision-resistant one-way hash function (we are using SHA-256,
// ofcouse given enough universes nothing is collision resistant)
func h(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// hsk must be a secure MAC function h (here we are using HMAC with SHA-256 and a secret key)
func hsk(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// fssAggUpd updates key using hash of previous key
func fssAggUpd(prevKey []byte) []byte {
	return h(prevKey)
}

// FssAggSig takes the current key, aggregated signature so far and a message,
// calculates the message MAC, updated aggregated signature and updates the key
// for forward security. It returns the aggregated signature plus the updated key.
func fssAggSig(key, aggMAC, message []byte) ([]byte, []byte) {
	var aggSig []byte

	// generate MAC for current message and aggregate current MAC with previous MACs
	curMAC := hsk(key, message)
	aggSig = h(append(aggMAC, curMAC...))

	// update key for forward security
	nextKey := fssAggUpd(key)

	return nextKey, aggSig
}

// FssAggVer verifies aggregated signature over messages, accepting the initial
// secret key and the aggregate signature, returning a boolean indicating the
// verification result.
func fssAggVer(secretKey, aggSig []byte, messages [][]byte) bool {
	key := secretKey
	var computedAggSig []byte

	for _, message := range messages {
		// generate MAC for current message
		curMAC := hsk(key, message)
		// aggregate current MAC with previous MACs
		computedAggSig = h(append(computedAggSig, curMAC...))

		// update key
		key = fssAggUpd(key)
	}

	// this compare is constant time, so no time leak and attack.
	return hmac.Equal(computedAggSig, aggSig)
}

func evolveKey(secretKey []byte, num uint64) []byte {
	key := secretKey
	for i := uint64(0); i < num; i++ {
		key = fssAggUpd(key)
	}
	return key
}
