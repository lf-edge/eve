// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

const (
	// RunWwanDir : directory where config/status/metrics are exchanged between
	// nim and wwan microservice.
	RunWwanDir = "/run/wwan/"
	// WwanConfigPath : LTE configuration submitted by NIM to wwan microservice.
	WwanConfigPath = RunWwanDir + "config.json"
	// WwanStatusPath : LTE status data published by wwan microservice.
	WwanStatusPath = RunWwanDir + "status.json"
	// WwanMetricsPath : LTE metrics published by wwan microservice.
	WwanMetricsPath = RunWwanDir + "metrics.json"
)
