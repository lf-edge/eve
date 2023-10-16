// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// CipherMetrics are metrics from one agent
type CipherMetrics struct {
	AgentName    string
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

// Key - key for pubsub
func (cipherMetric CipherMetrics) Key() string {
	return "global"
}

// LogCreate :
func (cipherMetric CipherMetrics) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.CipherMetricsLogType, "",
		nilUUID, cipherMetric.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("Cipher metric create")
}

// LogModify :
func (cipherMetric CipherMetrics) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.CipherMetricsLogType, "",
		nilUUID, cipherMetric.LogKey())

	oldAcMetric, ok := old.(CipherMetrics)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of CipherMetrics type")
	}
	// XXX remove? XXX huge?
	logObject.CloneAndAddField("diff", cmp.Diff(oldAcMetric, cipherMetric)).
		Metricf("Cipher metric modify")
}

// LogDelete :
func (cipherMetric CipherMetrics) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.CipherMetricsLogType, "",
		nilUUID, cipherMetric.LogKey())
	logObject.Metricf("Cipher metric delete")

	base.DeleteLogObject(logBase, cipherMetric.LogKey())
}

// LogKey :
func (cipherMetric CipherMetrics) LogKey() string {
	return string(base.CipherMetricsLogType) + "-" + cipherMetric.Key()
}
