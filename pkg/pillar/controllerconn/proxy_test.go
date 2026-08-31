// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllerconn_test

import (
	"encoding/base64"
	"net/url"
	"testing"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

// pacReturning builds a base64-encoded PAC file whose FindProxyForURL
// always returns the given string.
func pacReturning(result string) string {
	js := "function FindProxyForURL(url, host) { return \"" + result + "\"; }"
	return base64.StdEncoding.EncodeToString([]byte(js))
}

func dnsWithPac(pac string) *types.DeviceNetworkStatus {
	return &types.DeviceNetworkStatus{
		Ports: []types.NetworkPortStatus{
			{
				IfName:      "eth0",
				ProxyConfig: types.ProxyConfig{Pacfile: pac},
			},
		},
	}
}

// TestLookupProxyMalformedPAC is a regression test for an index-out-of-range
// panic triggered by a PAC result that has no space-separated address (e.g.
// "PROXY" or ""). Such a result must yield an error, not crash the process.
func TestLookupProxyMalformedPAC(t *testing.T) {
	g := NewWithT(t)
	log := base.NewSourceLogObject(logrus.StandardLogger(), "proxytest", 0)

	for _, result := range []string{
		"PROXY",  // type token, no address
		"",       // empty result
		"PROXY ", // trailing space handled by Fields, still no address
	} {
		dns := dnsWithPac(pacReturning(result))
		var proxy *url.URL
		var err error
		g.Expect(func() {
			proxy, err = controllerconn.LookupProxy(log, dns, "eth0", "http://example.com")
		}).ToNot(Panic(), "result %q must not panic", result)
		g.Expect(err).To(HaveOccurred(), "result %q should error", result)
		g.Expect(proxy).To(BeNil())
	}
}

// TestLookupProxyValidPAC makes sure the fix did not break the happy path.
func TestLookupProxyValidPAC(t *testing.T) {
	g := NewWithT(t)
	log := base.NewSourceLogObject(logrus.StandardLogger(), "proxytest", 0)

	dns := dnsWithPac(pacReturning("PROXY 1.2.3.4:8080"))
	proxy, err := controllerconn.LookupProxy(log, dns, "eth0", "http://example.com")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(proxy).ToNot(BeNil())
	g.Expect(proxy.Host).To(Equal("1.2.3.4:8080"))
}
