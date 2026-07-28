// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package netutils

import (
	"encoding/json"
	"net"
)

// HostnameOrIP holds either a literal IP address or a hostname.
// It stores both the original string and the parsed IP (if valid).
type HostnameOrIP struct {
	raw string // original string
	ip  net.IP // parsed IP if raw is a literal IP, nil if hostname
}

// NewHostnameOrIP creates a HostnameOrIP from a string.
func NewHostnameOrIP(s string) HostnameOrIP {
	return HostnameOrIP{
		raw: s,
		ip:  net.ParseIP(s),
	}
}

// NewHostnameOrIPs creates a slice of HostnameOrIP from one or more string values.
func NewHostnameOrIPs(values ...string) []HostnameOrIP {
	result := make([]HostnameOrIP, len(values))
	for i, s := range values {
		result[i] = NewHostnameOrIP(s)
	}
	return result
}

// EqualHostnameOrIPs compares two HostnameOrIP values for equality.
func EqualHostnameOrIPs(a, b HostnameOrIP) bool {
	return a.Equal(b)
}

// String returns the original string (IP or hostname).
func (h HostnameOrIP) String() string {
	return h.raw
}

// IsIP returns true if this is a literal IP.
func (h HostnameOrIP) IsIP() bool {
	return h.ip != nil
}

// GetIP returns the literal IP.
func (h HostnameOrIP) GetIP() net.IP {
	return h.ip
}

// Equal compares two HostnameOrIP values for equality.
func (h HostnameOrIP) Equal(h2 HostnameOrIP) bool {
	if h.IsIP() != h2.IsIP() {
		return false
	}
	if h.IsIP() {
		return h.ip.Equal(h2.ip)
	}
	return h.raw == h2.raw
}

// MarshalJSON serializes HostnameOrIP as a string.
func (h HostnameOrIP) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.raw)
}

// UnmarshalJSON parses from string and sets IP if valid.
func (h *HostnameOrIP) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	h.raw = s
	h.ip = net.ParseIP(s)
	return nil
}
