// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nettrace

import (
	"io"
)

// tracedHTTPBody wraps HTTP request/response body to determine and publish traces
// informing about the content length.
type tracedHTTPBody struct {
	httpReqID   TraceID
	tracer      networkTracer
	isRequest   bool // false for response body
	wrappedBody io.ReadCloser
	length      uint64
}

// HTTPBodyTrace is used to signal how many bytes of HTTP req/resp body was already read.
type HTTPBodyTrace struct {
	HTTPReqID   TraceID
	ISRequest   bool
	ReadBodyLen uint64
	EOF         bool
}

func (HTTPBodyTrace) isInternalNetTrace() {}

func newTracedHTTPBody(httpReqID TraceID, tracer networkTracer, isReq bool,
	body io.ReadCloser) *tracedHTTPBody {
	return &tracedHTTPBody{
		httpReqID:   httpReqID,
		tracer:      tracer,
		isRequest:   isReq,
		wrappedBody: body,
	}
}

func (hbt *tracedHTTPBody) Read(p []byte) (n int, err error) {
	n, err = hbt.wrappedBody.Read(p)
	hbt.length += uint64(n)
	hbt.tracer.publishTrace(HTTPBodyTrace{
		HTTPReqID:   hbt.httpReqID,
		ISRequest:   hbt.isRequest,
		ReadBodyLen: hbt.length,
		EOF:         err == io.EOF,
	})
	return n, err
}

func (hbt *tracedHTTPBody) Close() (err error) {
	return hbt.wrappedBody.Close()
}

// httpBodyWithWrite is used when wrappedBody implements Write.
type httpBodyWithWrite struct {
	*tracedHTTPBody
}

func (hb *httpBodyWithWrite) Write(p []byte) (n int, err error) {
	return hb.wrappedBody.(io.Writer).Write(p)
}
