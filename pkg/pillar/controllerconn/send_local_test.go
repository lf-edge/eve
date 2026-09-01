// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllerconn_test

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestSendLocalRejectsOversizeResponse is a regression test for the response
// cap on SendLocal (CWE-400). A local endpoint is served by an application on
// the device, which is untrusted; an oversized body must be rejected rather
// than read into memory without limit.
func TestSendLocalRejectsOversizeResponse(test *testing.T) {
	t := NewGomegaWithT(test)

	// maxLocalResponseSize is 1 MiB (unexported); answer with more than that.
	overCap := (1 << 20) + 1024
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.Write(bytes.Repeat([]byte("z"), overCap))
		}))
	defer server.Close()

	var dns types.DeviceNetworkStatus
	client := makeControllerClient(test, &dns, controllerconn.NewAgentMetrics())

	_, contents, err := client.SendLocal(
		server.URL, "lo", net.ParseIP("127.0.0.1"), nil, "")
	t.Expect(err).To(HaveOccurred())
	t.Expect(err.Error()).To(ContainSubstring("exceeds max size"))
	t.Expect(contents).To(BeNil())
}

// TestSendLocalAcceptsSmallResponse makes sure the cap does not break the normal
// case: a small body is returned to the caller unchanged.
func TestSendLocalAcceptsSmallResponse(test *testing.T) {
	t := NewGomegaWithT(test)

	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("hello-local"))
		}))
	defer server.Close()

	var dns types.DeviceNetworkStatus
	client := makeControllerClient(test, &dns, controllerconn.NewAgentMetrics())

	resp, contents, err := client.SendLocal(
		server.URL, "lo", net.ParseIP("127.0.0.1"), nil, "")
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(resp).ToNot(BeNil())
	t.Expect(resp.StatusCode).To(Equal(http.StatusOK))
	t.Expect(string(contents)).To(Equal("hello-local"))
}
