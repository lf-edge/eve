// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

// This file models the "proxy mess" cleanup as contract types, exercising the
// two constructs typify handles poorly: a string enum (vs EVE's int enum) and
// a data-carrying tagged union (vs EVE's flat struct with mode flags).

// ProxyScheme is the protocol of an explicitly configured proxy server.
// On the wire it is a string ("http"), not EVE's magic uint8 (0..4).
type ProxyScheme string

// ProxyScheme enumerates the supported proxy protocols.
const (
	ProxySchemeHTTP  ProxyScheme = "http"
	ProxySchemeHTTPS ProxyScheme = "https"
	ProxySchemeSOCKS ProxyScheme = "socks"
	ProxySchemeFTP   ProxyScheme = "ftp"
)

// ProxyServer is one explicitly configured proxy.
type ProxyServer struct {
	Scheme ProxyScheme `json:"scheme"`
	Host   string      `json:"host"`
	Port   uint16      `json:"port"`
}

// ProxySettings is a tagged union keyed by "mode" — the clean replacement for
// EVE's flat ProxyConfig where manual/PAC/WPAD were ambiguous coexisting flags.
//
//monitorapi:union tag=mode
type ProxySettings interface{ isProxySettings() }

// ProxyNone — no proxy. Serializes as {"mode":"none"}.
type ProxyNone struct{}

// ProxyManual — explicit per-protocol servers.
type ProxyManual struct {
	Servers    []ProxyServer `json:"servers"`
	Exceptions []string      `json:"exceptions,omitempty"`
	// CertPEM are extra CA certificates (PEM text) to trust for the proxy.
	CertPEM []string `json:"certPem,omitempty"`
}

// ProxyPac — proxy auto-config file.
type ProxyPac struct {
	PacFile string `json:"pacFile"`
}

// ProxyWpad — WPAD auto-discovery; URL is the resolved value, if any.
type ProxyWpad struct {
	URL *string `json:"url,omitempty"`
}

func (ProxyNone) isProxySettings()   {}
func (ProxyManual) isProxySettings() {}
func (ProxyPac) isProxySettings()    {}
func (ProxyWpad) isProxySettings()   {}

// NetworkProxy is a sample message type that carries the proxy union as a
// field — exercises the generated parent UnmarshalJSON dispatch.
type NetworkProxy struct {
	Port  string        `json:"port"`
	Proxy ProxySettings `json:"proxy"`
}
