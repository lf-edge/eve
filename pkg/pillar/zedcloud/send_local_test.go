// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedcloud

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

func testSendLocalContext() ZedCloudContext {
	log := base.NewSourceLogObject(logrus.New(), "zedcloud-sendlocal-test", 0)
	return NewContext(log, ContextOptions{SendTimeout: 5, DialTimeout: 5})
}

// TestSendLocalRejectsOversizeResponse verifies that an untrusted local endpoint
// cannot cause SendLocal to buffer more than the 1 MiB response limit.
func TestSendLocalRejectsOversizeResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("z"), maxLocalResponseSize+1024))
	}))
	defer server.Close()

	ctx := testSendLocalContext()
	_, contents, err := SendLocal(&ctx, server.URL, "lo", net.ParseIP("127.0.0.1"), 0, nil, "")
	if err == nil || !strings.Contains(err.Error(), "exceeds max size") {
		t.Fatalf("expected oversize error, got %v", err)
	}
	if contents != nil {
		t.Fatalf("expected no response contents, got %d bytes", len(contents))
	}
}

// TestSendLocalAcceptsSmallResponse verifies that a normal local response
// passes through the size limit unchanged.
func TestSendLocalAcceptsSmallResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello-local"))
	}))
	defer server.Close()

	ctx := testSendLocalContext()
	resp, contents, err := SendLocal(&ctx, server.URL, "lo", net.ParseIP("127.0.0.1"), 0, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected response: %v", resp)
	}
	if string(contents) != "hello-local" {
		t.Fatalf("unexpected response contents: %q", contents)
	}
}
