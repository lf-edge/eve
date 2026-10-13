// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

// These types describe the JSON payload served by the mgmtproxy agent's
// GET /healthz endpoint (127.0.0.1:5443/healthz). They are exported here,
// rather than kept private to the agent, so other components (e.g. edgeview)
// can unmarshal and process the snapshot, and so the wire contract of
// /healthz is documented in one place. The JSON tags are the contract — do
// not change them without updating consumers.

// MgmtProxyPortSummary describes one management port as seen by mgmtproxy's
// cost-aware dialer, for /healthz output.
type MgmtProxyPortSummary struct {
	IfName     string `json:"ifname"`
	Cost       uint8  `json:"cost"`
	IsMgmt     bool   `json:"isMgmt"`
	HasError   bool   `json:"hasError,omitempty"`
	LastError  string `json:"lastError,omitempty"`
	NumAddrs   int    `json:"numAddrs"`
	UsableAddr string `json:"usableAddr,omitempty"`
}

// MgmtProxyHealthz is the JSON snapshot returned by mgmtproxy's GET /healthz:
// listener state, the effective max port cost, the visible management ports,
// traffic counters, and the last success/error with timestamps.
type MgmtProxyHealthz struct {
	Listening         string                 `json:"listening"`
	CNI0Listening     bool                   `json:"cni0Listening"`
	Ready             bool                   `json:"ready"`
	MaxPortCost       uint8                  `json:"maxPortCost"`
	Ports             []MgmtProxyPortSummary `json:"ports"`
	Requests          uint64                 `json:"requests"`
	DialFailures      uint64                 `json:"dialFailures"`
	NotReady          uint64                 `json:"notReady"`
	TunnelIdleClosed  uint64                 `json:"tunnelIdleClosed"`
	BytesUp           uint64                 `json:"bytesUp"`
	BytesDown         uint64                 `json:"bytesDown"`
	SuccessByPort     map[string]uint64      `json:"successByPort"`
	FailureByPort     map[string]uint64      `json:"failureByPort"`
	LastSuccessTime   string                 `json:"lastSuccessTime,omitempty"`
	LastSuccessTarget string                 `json:"lastSuccessTarget,omitempty"`
	LastSuccessPort   string                 `json:"lastSuccessPort,omitempty"`
	LastSuccessCost   uint8                  `json:"lastSuccessCost,omitempty"`
	LastErrorTime     string                 `json:"lastErrorTime,omitempty"`
	LastError         string                 `json:"lastError,omitempty"`
}
