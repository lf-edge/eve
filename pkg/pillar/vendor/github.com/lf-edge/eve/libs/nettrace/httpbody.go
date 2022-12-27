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

// httpBodyTrace is used to signal how many bytes of HTTP req/resp body was already read.
type httpBodyTrace struct {
	httpReqID   TraceID
	isRequest   bool
	readBodyLen uint64
	eof         bool
}

func (httpBodyTrace) isInternalNetTrace() {}

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
	hbt.tracer.publishTrace(httpBodyTrace{
		httpReqID:   hbt.httpReqID,
		isRequest:   hbt.isRequest,
		readBodyLen: hbt.length,
		eof:         err == io.EOF,
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
