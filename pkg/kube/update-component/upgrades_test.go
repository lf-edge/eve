// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestFetchManifest(t *testing.T) {
	const body = "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: cdi\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok.yaml" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	file, err := fetchManifest(srv.URL + "/ok.yaml")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	defer func() { _ = os.Remove(file) }()
	got, err := os.ReadFile(file)
	if err != nil || string(got) != body {
		t.Fatalf("fetched %q, %v; want %q", got, err, body)
	}

	if file, err := fetchManifest(srv.URL + "/missing.yaml"); err == nil {
		_ = os.Remove(file)
		t.Fatal("fetch of a missing manifest succeeded")
	}
}
