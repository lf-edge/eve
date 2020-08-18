// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"
)

// CipherMetricsMap maps from an agentname string to some metrics
type CipherMetricsMap map[string]CipherMetrics

// CipherMetrics are metrics from one agent
type CipherMetrics struct {
	FailureCount uint64
	SuccessCount uint64
	LastFailure  time.Time
	LastSuccess  time.Time
	// One for each value of CipherError
	TypeCounters []uint64
}

// CipherError is a specific error for object encryption
// Must match CipherError in the api/proto/metrics.proto
// Note that NoData isn't an error; it means there was nothing to decrypt
type CipherError uint8

// Invalid should not be used
const (
	Invalid           CipherError = iota
	NotReady                      // Not yet received ECDH controller cert
	DecryptFailed                 // ECDH decrypt failed
	UnmarshalFailed               // Failed protobuf decode post decryption
	CleartextFallback             // Failure then using cleartext
	MissingFallback               // Failed and no cleartext to fall back to
	NoCipher                      // Only cleartext received
	NoData                        // No data to encrypt/decrypt

	MaxCipherError // Must be last
)
