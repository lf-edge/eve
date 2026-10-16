// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	info "github.com/lf-edge/eve-api/go/info"
	nestedapp "github.com/lf-edge/eve-api/go/nestedappinstancemetrics"
	"github.com/lf-edge/eve/pkg/pillar/types"
	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/types/known/timestamppb"
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

	notFoundSrv := httptest.NewServer(http.NotFoundHandler())
	defer notFoundSrv.Close()
	_, err = fetchHTTPData(notFoundSrv.URL)
	var statusErr *httpStatusError
	g.Expect(errors.As(err, &statusErr)).To(BeTrue())
	g.Expect(statusErr.statusCode).To(Equal(http.StatusNotFound))
}

func rtErr(desc string, sev info.Severity, ts *timestamppb.Timestamp) *nestedapp.RuntimeErrorInfo {
	return &nestedapp.RuntimeErrorInfo{Description: desc, Severity: sev, Timestamp: ts}
}

func TestRuntimeStatusToErrorDescription(t *testing.T) {
	const (
		sevErr  = info.Severity_SEVERITY_ERROR
		sevWarn = info.Severity_SEVERITY_WARNING
	)
	older := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newest := older.Add(time.Hour)
	huge := "head" + strings.Repeat("x", 1<<20) + "tail"
	mixed := []*nestedapp.RuntimeErrorInfo{
		rtErr("warn-a", sevWarn, nil), rtErr("err-b", sevErr, nil),
		rtErr("warn-c", sevWarn, nil), rtErr("err-a", sevErr, nil),
		rtErr("warn-b", sevWarn, nil),
	}
	reversed := make([]*nestedapp.RuntimeErrorInfo, len(mixed))
	for i, e := range mixed {
		reversed[len(mixed)-1-i] = e
	}
	mixedWant := types.ErrorDescription{
		Error: "err-a; err-b; warn-a; warn-b; " +
			"[1 additional runtime messages omitted due to size limits]",
		ErrorSeverity: types.ErrorSeverityError,
	}

	tests := []struct {
		name string
		errs []*nestedapp.RuntimeErrorInfo
		want types.ErrorDescription
	}{
		{name: "only empty descriptions", errs: []*nestedapp.RuntimeErrorInfo{
			rtErr("", sevErr, timestamppb.New(newest)),
		}},
		{name: "oversized entry is truncated", errs: []*nestedapp.RuntimeErrorInfo{
			rtErr(huge, sevErr, nil),
		}, want: types.ErrorDescription{
			Error:         types.TruncateError(huge, maxRuntimeStatusEntryLen),
			ErrorSeverity: types.ErrorSeverityError,
		}},
		{name: "errors beyond the entry limit are omitted", errs: []*nestedapp.RuntimeErrorInfo{
			rtErr("e5", sevErr, nil), rtErr("e4", sevErr, nil), rtErr("w0", sevWarn, nil),
			rtErr("e3", sevErr, nil), rtErr("e2", sevErr, nil), rtErr("e1", sevErr, nil),
			rtErr("e0", sevErr, nil),
		}, want: types.ErrorDescription{
			Error: "e0; e1; e2; e3; " +
				"[3 additional runtime messages omitted due to size limits]",
			ErrorSeverity: types.ErrorSeverityError,
		}},
		{name: "warnings are dropped before errors", errs: mixed, want: mixedWant},
		{name: "input order does not matter", errs: reversed, want: mixedWant},
		{name: "unspecified and unknown severities rank as errors", errs: []*nestedapp.RuntimeErrorInfo{
			rtErr("n", info.Severity_SEVERITY_NOTICE, nil),
			rtErr("w", sevWarn, nil),
			rtErr("x", info.Severity(99), nil),
			rtErr("u", info.Severity_SEVERITY_UNSPECIFIED, nil),
		}, want: types.ErrorDescription{
			Error:         "u; x; w; n",
			ErrorSeverity: types.ErrorSeverityError,
		}},
		{name: "latest timestamp includes omitted entries", errs: []*nestedapp.RuntimeErrorInfo{
			rtErr("a", sevErr, timestamppb.New(older)),
			rtErr("b", sevErr, nil),
			rtErr("c", sevErr, timestamppb.New(time.Unix(0, 0))),
			rtErr("d", sevErr, nil),
			rtErr("e", sevErr, timestamppb.New(newest)),
		}, want: types.ErrorDescription{
			Error: "a; b; c; d; " +
				"[1 additional runtime messages omitted due to size limits]",
			ErrorTime:     newest,
			ErrorSeverity: types.ErrorSeverityError,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			got := runtimeStatusToErrorDescription(&nestedapp.RuntimeStatus{Err: tt.errs})
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

// TestRuntimeStatusSizeBound checks that a hostile runtime cannot make the
// published AppRuntimeStatus approach the pubsub message limit.
func TestRuntimeStatusSizeBound(t *testing.T) {
	g := NewWithT(t)
	rs := &nestedapp.RuntimeStatus{}
	for i := 0; i < 10; i++ {
		desc := fmt.Sprintf("%d", i) + strings.Repeat("x", 1<<20)
		rs.Err = append(rs.Err, rtErr(desc, info.Severity_SEVERITY_ERROR, nil))
	}
	status := types.AppRuntimeStatus{UUID: "6ba7b810-9dad-11d1-80b4-00c04fd430c8"}
	status.SetErrorDescription(runtimeStatusToErrorDescription(rs))
	data, err := json.Marshal(status)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(len(data)).To(BeNumerically("<", 1024))
}
