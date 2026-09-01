// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
)

// TestLimitedReadCloser is a regression test for the response-body cap applied
// to the untrusted app Docker endpoint (CWE-400). Reads must stay bounded and
// return an error once the stream reaches the configured size instead of
// allocating without limit.
func TestLimitedReadCloser(t *testing.T) {
	g := NewWithT(t)

	newReader := func(n int) *limitedReadCloser {
		body := io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("a"), n)))
		// remaining is the number of bytes that may be consumed before the next
		// read is rejected; getAppContainers sets it to limit+1.
		return &limitedReadCloser{inner: body, remaining: 10}
	}

	// Under the limit: the whole body is returned, no error.
	out, err := io.ReadAll(newReader(9))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(out).To(HaveLen(9))

	// At the limit: rejected.
	_, err = io.ReadAll(newReader(10))
	g.Expect(err).To(HaveOccurred())

	// Well over the limit: rejected, and no more than the cap is ever read.
	_, err = io.ReadAll(newReader(1000))
	g.Expect(err).To(HaveOccurred())
}

// TestLimitedResponseTransport verifies the transport wrapper caps the response
// body seen by a client (as used by the Docker client in getAppContainers): a
// body larger than the limit fails to read, a smaller one reads cleanly.
func TestLimitedResponseTransport(t *testing.T) {
	g := NewWithT(t)

	serve := func(size int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				w.Write(bytes.Repeat([]byte("x"), size))
			}))
	}
	client := func() *http.Client {
		return &http.Client{Transport: &limitedResponseTransport{
			base: http.DefaultTransport, limit: 512}}
	}

	// Body within the cap: reads fine.
	srv := serve(400)
	defer srv.Close()
	resp, err := client().Get(srv.URL)
	g.Expect(err).ToNot(HaveOccurred())
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(body).To(HaveLen(400))

	// Body over the cap: the read fails instead of allocating without limit.
	bigSrv := serve(4096)
	defer bigSrv.Close()
	resp, err = client().Get(bigSrv.URL)
	g.Expect(err).ToNot(HaveOccurred())
	_, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	g.Expect(err).To(HaveOccurred())
}

// TestFetchHTTPData covers the happy path and the non-200 rejection of the
// nested-app runtime metrics fetch.
func TestFetchHTTPData(t *testing.T) {
	g := NewWithT(t)

	okSrv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("payload"))
		}))
	defer okSrv.Close()
	data, err := fetchHTTPData(okSrv.URL)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(string(data)).To(Equal("payload"))

	errSrv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
	defer errSrv.Close()
	_, err = fetchHTTPData(errSrv.URL)
	g.Expect(err).To(HaveOccurred())
}
