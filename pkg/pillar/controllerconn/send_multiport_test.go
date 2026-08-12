// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllerconn_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// loopbackPort describes a management port which reaches the test server from
// a distinct loopback source address, so that the handler can tell the ports
// apart and answer each differently.
func loopbackPort(ifName string, srcIP string, cost uint8) types.NetworkPortStatus {
	return types.NetworkPortStatus{
		IfName:       ifName,
		Phylabel:     ifName,
		Logicallabel: ifName,
		IsMgmt:       true,
		IsL3Port:     true,
		Up:           true,
		Cost:         cost,
		AddrInfoList: []types.AddrInfo{{Addr: net.ParseIP(srcIP)}},
		// Any DNS server will do, the request goes to a literal IP address.
		DNSServers:     []net.IP{net.ParseIP("127.0.0.1")},
		DefaultRouters: []net.IP{net.ParseIP("127.0.0.1")},
	}
}

// The status reported to the caller must describe the port which delivered the
// request, not one that failed before it. Otherwise a message that reached the
// controller looks like a failure and gets sent a second time.
func TestSendOnAllIntfStatusComesFromDeliveringPort(test *testing.T) {
	t := NewGomegaWithT(test)

	const failingSrcIP = "127.0.0.2"
	const workingSrcIP = "127.0.0.1"

	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err == nil && host == failingSrcIP {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
	defer server.Close()

	// The cheaper port is tried first and is the one answered with a 503.
	var dns types.DeviceNetworkStatus
	dns.Ports = []types.NetworkPortStatus{
		loopbackPort("fakefail", failingSrcIP, 0),
		loopbackPort("fakework", workingSrcIP, 1),
	}
	client := makeControllerClient(test, &dns, controllerconn.NewAgentMetrics())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rv, err := client.SendOnAllIntf(ctx, server.URL+"/info", nil,
		controllerconn.RequestOptions{AllowLoopbackDNS: true})

	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(rv.HTTPResp).ToNot(BeNil())
	t.Expect(rv.HTTPResp.StatusCode).To(Equal(http.StatusOK))
	t.Expect(rv.LastHTTPStatusCode).To(Equal(http.StatusOK))
	t.Expect(rv.Status).To(Equal(types.SenderStatusNone))
}

// When no port delivers the request, the status code the controller did answer
// with has to survive, so that the caller can tell a rejection from a link that
// never reached the controller.
func TestSendOnAllIntfReportsStatusCodeWhenAllPortsFail(test *testing.T) {
	t := NewGomegaWithT(test)

	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
	defer server.Close()

	var dns types.DeviceNetworkStatus
	dns.Ports = []types.NetworkPortStatus{
		loopbackPort("fakefail", "127.0.0.2", 0),
		loopbackPort("fakefail2", "127.0.0.1", 1),
	}
	client := makeControllerClient(test, &dns, controllerconn.NewAgentMetrics())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rv, err := client.SendOnAllIntf(ctx, server.URL+"/info", nil,
		controllerconn.RequestOptions{AllowLoopbackDNS: true})

	t.Expect(err).To(HaveOccurred())
	t.Expect(rv.HTTPResp).To(BeNil())
	t.Expect(rv.LastHTTPStatusCode).To(Equal(http.StatusServiceUnavailable))
	t.Expect(rv.Status).To(Equal(types.SenderStatusUpgrade))
}
