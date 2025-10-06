// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nettrace

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
)

// ctxKey is an unexported type for context keys defined in this package.
// This prevents collisions with keys defined in other packages.
type ctxKey int

const (
	// httpReqIDKey is used to pass HTTP request TraceID into the context
	// from RoundTripper and carry it all the way into the Dial call.
	httpReqIDKey ctxKey = iota
)

func withHTTPReqID(ctx context.Context, httpReqID TraceID) context.Context {
	return context.WithValue(ctx, httpReqIDKey, httpReqID)
}

func getHTTPReqID(ctx context.Context) TraceID {
	reqID, ok := ctx.Value(httpReqIDKey).(TraceID)
	if !ok {
		var undefined TraceID
		return undefined
	}
	return reqID
}

// tracedRoundTripper implements http.RoundTripper.
type tracedRoundTripper struct {
	tracer httpClientTracer
	opts   WithHTTPReqTrace
}

type httpClientTracer interface {
	networkTracer
	getHTTPTransport() http.RoundTripper
	proxyForRequest(req *http.Request) (*url.URL, error)
}

// tracedHTTPReq is used to collect and publish traces for a single HTTP request
// (1 round-trip).
type tracedHTTPReq struct {
	httpReqID  TraceID
	tracer     httpClientTracer
	tlsStartAt Timestamp
	tlsCounter uint
	proxyURL   *url.URL
}

// HTTPConnTrace is published when we learn which connection is going to be used
// for a given HTTP request.
type HTTPConnTrace struct {
	HTTPReqID TraceID
	Conn      net.Conn
}

func (HTTPConnTrace) isInternalNetTrace() {}

// TLSTrace is published when TLS tunnel is established or fails to establish.
type TLSTrace struct {
	TLSTunnelTrace // TCPConn is not set here
	HTTPReqID      TraceID
	ForProxy       bool
}

func (TLSTrace) isInternalNetTrace() {}

// HTTPReqTraceEnv is published just before RoundTrip is triggered.
type HTTPReqTraceEnv struct {
	HTTPReqID  TraceID
	ProtoMajor uint8
	ProtoMinor uint8
	SentAt     Timestamp
	ReqMethod  string
	ReqURL     string
	Header     HTTPHeader
	NetProxy   string
}

func (HTTPReqTraceEnv) isInternalNetTrace() {}

// HTTPRespTrace is published when RoundTrip returns.
type HTTPRespTrace struct {
	HTTPReqID  TraceID
	ProtoMajor uint8
	ProtoMinor uint8
	RtErr      error
	RecvAt     Timestamp
	StatusCode int
	Header     HTTPHeader
}

func (HTTPRespTrace) isInternalNetTrace() {}

func newTracedRoundTripper(
	forTracer httpClientTracer, opts WithHTTPReqTrace) *tracedRoundTripper {
	return &tracedRoundTripper{
		tracer: forTracer,
		opts:   opts,
	}
}

// RoundTrip executes a single *traced* HTTP transaction.
func (rt *tracedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	reqID := IDGenerator()

	var netProxy string
	proxyURL, err := rt.tracer.proxyForRequest(req)
	if err == nil && proxyURL != nil {
		netProxy = proxyURL.String()
	}

	// tracedHTTPReq used to trace TLS tunnels + find net.Conn for the HTTP request.
	rtTracer := &tracedHTTPReq{
		tracer:    rt.tracer,
		httpReqID: reqID,
		proxyURL:  proxyURL,
	}
	ctx := req.Context()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn:           rtTracer.gotConn,
		TLSHandshakeStart: rtTracer.tlsHandshakeStart,
		TLSHandshakeDone:  rtTracer.tlsHandshakeDone,
	})
	ctx = withHTTPReqID(ctx, reqID)
	req = req.WithContext(ctx)

	// tracedHTTPBody used to find out the request body length.
	if req.Body != nil {
		tracedBody := newTracedHTTPBody(reqID, rt.tracer, true, req.Body)
		if _, ok := req.Body.(io.WriterTo); ok {
			req.Body = &httpBodyWithWrite{tracedHTTPBody: tracedBody}
		} else {
			req.Body = tracedBody
		}
	}

	// Publish networkTrace about the HTTP request.
	reqTrace := HTTPReqTraceEnv{
		HTTPReqID:  reqID,
		ProtoMajor: uint8(req.ProtoMajor),
		ProtoMinor: uint8(req.ProtoMinor),
		SentAt:     rt.tracer.getRelTimestamp(),
		ReqMethod:  req.Method,
		ReqURL:     req.URL.String(),
		Header:     rt.captureHeader(req.Header),
		NetProxy:   netProxy,
	}
	rt.tracer.publishTrace(reqTrace)

	// Execute the HTTP request.
	resp, err := rt.tracer.getHTTPTransport().RoundTrip(req)

	// Publish networkTrace about the HTTP response.
	if err == nil && resp != nil {
		respTrace := HTTPRespTrace{
			HTTPReqID:  reqID,
			ProtoMajor: uint8(resp.ProtoMajor),
			ProtoMinor: uint8(resp.ProtoMinor),
			RecvAt:     rt.tracer.getRelTimestamp(),
			StatusCode: resp.StatusCode,
			Header:     rt.captureHeader(resp.Header),
		}
		rt.tracer.publishTrace(respTrace)
		// tracedHTTPBody used to find out the response body length.
		if resp.Body != nil {
			tracedBody := newTracedHTTPBody(reqID, rt.tracer, false, resp.Body)
			if _, ok := req.Body.(io.WriterTo); ok {
				resp.Body = &httpBodyWithWrite{tracedHTTPBody: tracedBody}
			} else {
				resp.Body = tracedBody
			}
		}
	}
	if err != nil {
		respTrace := HTTPRespTrace{
			HTTPReqID: reqID,
			RtErr:     err,
		}
		rt.tracer.publishTrace(respTrace)
	}
	return resp, err
}

func (rt *tracedRoundTripper) captureHeader(httpHdr http.Header) (hdr HTTPHeader) {
	if rt.opts.HeaderFields == HdrFieldsOptDisabled {
		return
	}
	for name, vals := range httpHdr {
		if rt.opts.ExcludeHeaderField != nil {
			if rt.opts.ExcludeHeaderField(name) {
				continue
			}
		}
		if rt.opts.HeaderFields == HdrFieldsOptNamesOnly {
			hdr = append(hdr, HTTPHeaderKV{FieldName: name})
			continue
		}
		for _, val := range vals {
			valLen := uint32(len(val))
			if rt.opts.HeaderFields == HdrFieldsOptValueLenOnly {
				val = ""
			}
			hdr = append(hdr, HTTPHeaderKV{
				FieldName:   name,
				FieldVal:    val,
				FieldValLen: valLen,
			})
		}
	}
	return hdr
}

func (t *tracedHTTPReq) gotConn(connInfo httptrace.GotConnInfo) {
	t.tracer.publishTrace(HTTPConnTrace{
		HTTPReqID: t.httpReqID,
		Conn:      connInfo.Conn,
	})
}

func (t *tracedHTTPReq) tlsHandshakeStart() {
	t.tlsStartAt = t.tracer.getRelTimestamp()
	t.tlsCounter++
}

func (t *tracedHTTPReq) tlsHandshakeDone(tlsState tls.ConnectionState, err error) {
	tlsTrace := TLSTrace{
		TLSTunnelTrace: TLSTunnelTrace{
			TraceID:          IDGenerator(),
			HandshakeBeginAt: t.tlsStartAt,
			HandshakeEndAt:   t.tracer.getRelTimestamp(),
			HandshakeErr:     errToString(err),
			DidResume:        tlsState.DidResume,
			CipherSuite:      tlsState.CipherSuite,
			NegotiatedProto:  tlsState.NegotiatedProtocol,
			ServerName:       tlsState.ServerName,
		},
		HTTPReqID: t.httpReqID,
	}
	var (
		certErr        x509.CertificateInvalidError
		hostnameErr    x509.HostnameError
		unknownAuthErr x509.UnknownAuthorityError
	)
	if errors.As(err, &certErr) {
		tlsTrace.PeerCerts = append(tlsTrace.PeerCerts, x509ToPeerCert(certErr.Cert))
	} else if errors.As(err, &hostnameErr) {
		tlsTrace.PeerCerts = append(tlsTrace.PeerCerts, x509ToPeerCert(hostnameErr.Certificate))
	} else if errors.As(err, &unknownAuthErr) {
		tlsTrace.PeerCerts = append(tlsTrace.PeerCerts, x509ToPeerCert(unknownAuthErr.Cert))
	} else {
		for _, peer := range tlsState.PeerCertificates {
			tlsTrace.PeerCerts = append(tlsTrace.PeerCerts, x509ToPeerCert(peer))
		}
	}
	if t.tlsCounter == 1 &&
		t.proxyURL != nil &&
		strings.ToLower(t.proxyURL.Scheme) == "https" {
		tlsTrace.ForProxy = true
	}
	t.tracer.publishTrace(tlsTrace)
	t.tlsStartAt = Timestamp{} // clear
}

func x509ToPeerCert(cert *x509.Certificate) PeerCert {
	return PeerCert{
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		NotBefore: Timestamp{Abs: cert.NotBefore},
		NotAfter:  Timestamp{Abs: cert.NotAfter},
		IsCA:      cert.IsCA,
	}
}
