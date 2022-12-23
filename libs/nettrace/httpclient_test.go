// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nettrace_test

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/libs/nettrace"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

func relTimeIsInBetween(t *GomegaWithT, timestamp, lowerBound, upperBound nettrace.Timestamp) {
	t.Expect(timestamp.IsRel).To(BeTrue())
	t.Expect(lowerBound.IsRel).To(BeTrue())
	t.Expect(upperBound.IsRel).To(BeTrue())
	t.Expect(timestamp.Rel >= lowerBound.Rel).To(BeTrue())
	t.Expect(timestamp.Rel <= upperBound.Rel).To(BeTrue())
}

func TestHTTPTracing(test *testing.T) {
	startTime := time.Now()
	t := NewWithT(test)

	// Options that do not require administrative privileges.
	opts := []nettrace.TraceOpt{
		&nettrace.WithLogging{
			CustomLogger: logrus.New(),
		},
		&nettrace.WithHTTPReqTrace{
			HeaderFields: nettrace.HdrFieldsOptWithValues,
		},
		&nettrace.WithSockTrace{},
		&nettrace.WithDNSQueryTrace{},
	}
	client, err := nettrace.NewHTTPClient(nettrace.HTTPClientCfg{
		PreferHTTP2:      true,
		ReqTimeout:       5 * time.Second,
		DisableKeepAlive: true,
	}, opts...)
	t.Expect(err).ToNot(HaveOccurred())

	req, err := http.NewRequest("GET", "https://www.example.com", nil)
	t.Expect(err).ToNot(HaveOccurred())
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(resp).ToNot(BeNil())
	t.Expect(resp.StatusCode).To(Equal(200))
	t.Expect(resp.Body).ToNot(BeNil())
	body := new(strings.Builder)
	_, err = io.Copy(body, resp.Body)
	t.Expect(err).ToNot(HaveOccurred())
	err = resp.Body.Close()
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(body.String()).To(ContainSubstring("<html>"))
	t.Expect(body.String()).To(ContainSubstring("</html>"))

	trace, pcap, err := client.GetTrace("GET www.example.com over HTTPS")
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(pcap).To(BeEmpty())

	t.Expect(trace.Description).To(Equal("GET www.example.com over HTTPS"))
	t.Expect(trace.TraceBeginAt.IsRel).To(BeFalse())
	t.Expect(trace.TraceBeginAt.Abs.After(startTime)).To(BeTrue())
	t.Expect(trace.TraceBeginAt.Abs.Before(time.Now())).To(BeTrue())
	traceBeginAsRel := nettrace.Timestamp{IsRel: true, Rel: 0}
	t.Expect(trace.TraceEndAt.IsRel).To(BeTrue())
	t.Expect(trace.TraceEndAt.Rel > 0).To(BeTrue())

	// Dial trace
	t.Expect(trace.Dials).To(HaveLen(1)) // no redirects
	dial := trace.Dials[0]
	t.Expect(dial.TraceID).ToNot(BeZero())
	relTimeIsInBetween(t, dial.DialBeginAt, traceBeginAsRel, trace.TraceEndAt)
	relTimeIsInBetween(t, dial.DialEndAt, dial.DialBeginAt, trace.TraceEndAt)
	t.Expect(dial.DialErr).To(BeZero())
	t.Expect(dial.SourceIP).To(BeZero())
	t.Expect(dial.DstAddress).To(Equal("www.example.com:443"))
	t.Expect(dial.ResolverDials).ToNot(BeEmpty())
	for _, resolvDial := range dial.ResolverDials {
		relTimeIsInBetween(t, resolvDial.DialBeginAt, dial.DialBeginAt, dial.DialEndAt)
		relTimeIsInBetween(t, resolvDial.DialEndAt, resolvDial.DialBeginAt, dial.DialEndAt)
		t.Expect(resolvDial.Nameserver).ToNot(BeZero())
		if !resolvDial.EstablishedConn.Undefined() {
			t.Expect(resolvDial.DialErr).To(BeZero())
			t.Expect(trace.UDPConns.Get(resolvDial.EstablishedConn)).ToNot(BeNil())
		}
	}
	t.Expect(dial.EstablishedConn).ToNot(BeZero())
	t.Expect(trace.TCPConns.Get(dial.EstablishedConn)).ToNot(BeNil())

	// DNS trace
	t.Expect(trace.DNSQueries).ToNot(BeEmpty())
	for _, dnsQuery := range trace.DNSQueries {
		t.Expect(dnsQuery.FromDial == dial.TraceID).To(BeTrue())
		t.Expect(dnsQuery.TraceID).ToNot(BeZero())
		udpConn := trace.UDPConns.Get(dnsQuery.Connection)
		t.Expect(udpConn).ToNot(BeNil())

		t.Expect(dnsQuery.DNSQueryMsgs).To(HaveLen(1))
		dnsMsg := dnsQuery.DNSQueryMsgs[0]
		relTimeIsInBetween(t, dnsMsg.SentAt, udpConn.SocketCreateAt, udpConn.ConnCloseAt)
		t.Expect(dnsMsg.Questions).To(HaveLen(1))
		t.Expect(dnsMsg.Questions[0].Name).To(Equal("www.example.com."))
		t.Expect(dnsMsg.Questions[0].Type).To(Or(
			Equal(nettrace.DNSResTypeA), Equal(nettrace.DNSResTypeAAAA)))
		t.Expect(dnsMsg.Truncated).To(BeFalse())

		t.Expect(dnsQuery.DNSReplyMsgs).To(HaveLen(1))
		dnsReply := dnsQuery.DNSReplyMsgs[0]
		relTimeIsInBetween(t, dnsReply.RecvAt, dnsMsg.SentAt, udpConn.ConnCloseAt)
		t.Expect(dnsReply.ID == dnsMsg.ID).To(BeTrue())
		t.Expect(dnsReply.RCode).To(Equal(nettrace.DNSRCodeNoError))
		t.Expect(dnsReply.Answers).ToNot(BeEmpty())
		t.Expect(dnsReply.Truncated).To(BeFalse())
	}

	// UDP connection trace
	t.Expect(trace.UDPConns).ToNot(BeEmpty())
	for _, udpConn := range trace.UDPConns {
		t.Expect(udpConn.TraceID).ToNot(BeZero())
		t.Expect(udpConn.FromDial == dial.TraceID).To(BeTrue())
		relTimeIsInBetween(t, udpConn.SocketCreateAt, dial.DialBeginAt, dial.DialEndAt)
		relTimeIsInBetween(t, udpConn.ConnCloseAt, udpConn.SocketCreateAt, dial.DialEndAt)
		t.Expect(net.ParseIP(udpConn.AddrTuple.SrcIP)).ToNot(BeNil())
		t.Expect(net.ParseIP(udpConn.AddrTuple.DstIP)).ToNot(BeNil())
		t.Expect(udpConn.AddrTuple.SrcPort).ToNot(BeZero())
		t.Expect(udpConn.AddrTuple.DstPort).ToNot(BeZero())
		t.Expect(udpConn.SocketTrace).ToNot(BeNil())
		t.Expect(udpConn.SocketTrace.SocketOps).ToNot(BeEmpty())
		for _, socketOp := range udpConn.SocketTrace.SocketOps {
			relTimeIsInBetween(t, socketOp.CallAt, udpConn.SocketCreateAt, udpConn.ConnCloseAt)
			relTimeIsInBetween(t, socketOp.ReturnAt, socketOp.CallAt, udpConn.ConnCloseAt)
		}
		t.Expect(udpConn.Conntract).To(BeNil()) // WithConntrack requires root privileges
		t.Expect(udpConn.TotalRecvBytes).ToNot(BeZero())
		t.Expect(udpConn.TotalSentBytes).ToNot(BeZero())
	}

	// HTTP request trace
	t.Expect(trace.HTTPRequests).To(HaveLen(1))
	httpReq := trace.HTTPRequests[0]
	t.Expect(httpReq.TraceID).ToNot(BeZero())
	t.Expect(httpReq.TCPConn.Undefined()).To(BeFalse())
	usedTCPConn := trace.TCPConns.Get(httpReq.TCPConn)
	t.Expect(usedTCPConn).ToNot(BeNil())
	t.Expect(httpReq.ProtoMajor).To(BeEquivalentTo(2))
	t.Expect(httpReq.ProtoMinor).To(BeEquivalentTo(0))
	t.Expect(httpReq.NetworkProxy).To(BeZero())
	relTimeIsInBetween(t, httpReq.ReqSentAt, traceBeginAsRel, trace.TraceEndAt)
	t.Expect(httpReq.ReqError).To(BeZero())
	t.Expect(httpReq.ReqMethod).To(Equal("GET"))
	t.Expect(httpReq.ReqURL).To(Equal("https://www.example.com"))
	t.Expect(httpReq.ReqHeader).ToNot(BeEmpty())
	acceptHdr := httpReq.ReqHeader.Get("Accept")
	t.Expect(acceptHdr).ToNot(BeNil())
	t.Expect(acceptHdr.FieldVal).To(Equal("text/html"))
	t.Expect(acceptHdr.FieldValLen).To(BeEquivalentTo(len(acceptHdr.FieldVal)))
	t.Expect(httpReq.ReqContentLen).To(BeZero())
	relTimeIsInBetween(t, httpReq.RespRecvAt, httpReq.ReqSentAt, trace.TraceEndAt)
	t.Expect(httpReq.RespStatusCode).To(Equal(200))
	t.Expect(httpReq.RespHeader).ToNot(BeEmpty())
	contentType := httpReq.RespHeader.Get("content-type")
	t.Expect(contentType).ToNot(BeNil())
	t.Expect(contentType.FieldVal).To(ContainSubstring("text/html"))
	t.Expect(contentType.FieldValLen).To(BeEquivalentTo(len(contentType.FieldVal)))
	t.Expect(httpReq.RespContentLen).ToNot(BeZero())

	// TCP connection traces
	// There can be multiple parallel connection attempts made as per Happy Eyeballs algorithm.
	t.Expect(trace.TCPConns).ToNot(BeEmpty())
	for _, tcpConn := range trace.TCPConns {
		t.Expect(tcpConn.TraceID).ToNot(BeZero())
		t.Expect(tcpConn.FromDial == dial.TraceID).To(BeTrue())
		t.Expect(tcpConn.Reused).To(BeFalse())
		t.Expect(net.ParseIP(tcpConn.AddrTuple.SrcIP)).ToNot(BeNil())
		t.Expect(net.ParseIP(tcpConn.AddrTuple.DstIP)).ToNot(BeNil())
		t.Expect(tcpConn.AddrTuple.SrcPort).ToNot(BeZero()) // TODO: this may fail for IPv6
		t.Expect(tcpConn.AddrTuple.DstPort).ToNot(BeZero())
		t.Expect(tcpConn.Conntract).To(BeNil()) // WithConntrack requires root privileges
		if tcpConn.TraceID != usedTCPConn.TraceID {
			// Not used for HTTP request in the end.
			continue
		}
		relTimeIsInBetween(t, tcpConn.HandshakeBeginAt, dial.DialBeginAt, dial.DialEndAt)
		relTimeIsInBetween(t, tcpConn.HandshakeEndAt, tcpConn.HandshakeBeginAt, dial.DialEndAt)
		relTimeIsInBetween(t, tcpConn.ConnCloseAt, tcpConn.HandshakeEndAt, trace.TraceEndAt)
		t.Expect(tcpConn.SocketTrace).ToNot(BeNil())
		t.Expect(tcpConn.SocketTrace.SocketOps).ToNot(BeEmpty())
		for _, socketOp := range tcpConn.SocketTrace.SocketOps {
			relTimeIsInBetween(t, socketOp.CallAt, tcpConn.HandshakeEndAt, tcpConn.ConnCloseAt)
			relTimeIsInBetween(t, socketOp.ReturnAt, socketOp.CallAt, tcpConn.ConnCloseAt)
		}
		t.Expect(tcpConn.TotalRecvBytes).ToNot(BeZero())
		t.Expect(tcpConn.TotalSentBytes).ToNot(BeZero())
	}

	// TLS tunnel trace
	t.Expect(trace.TLSTunnels).To(HaveLen(1))
	tlsTun := trace.TLSTunnels[0]
	t.Expect(tlsTun.TraceID).ToNot(BeZero())
	t.Expect(tlsTun.TCPConn == usedTCPConn.TraceID).To(BeTrue())
	t.Expect(httpReq.TLSTunnel == tlsTun.TraceID).To(BeTrue())
	t.Expect(httpReq.ProxyTLSTunnel.Undefined()).To(BeTrue())
	t.Expect(tlsTun.DidResume).To(BeFalse())
	relTimeIsInBetween(t, tlsTun.HandshakeBeginAt, usedTCPConn.HandshakeEndAt, usedTCPConn.ConnCloseAt)
	relTimeIsInBetween(t, tlsTun.HandshakeEndAt, tlsTun.HandshakeBeginAt, usedTCPConn.ConnCloseAt)
	t.Expect(tlsTun.HandshakeErr).To(BeZero())
	t.Expect(tlsTun.ServerName).To(Equal("www.example.com"))
	t.Expect(tlsTun.NegotiatedProto).To(Equal("h2"))
	t.Expect(tlsTun.CipherSuite).ToNot(BeZero())
	t.Expect(tlsTun.PeerCerts).To(HaveLen(2))
	peerCert := tlsTun.PeerCerts[0]
	t.Expect(peerCert.IsCA).To(BeFalse())
	t.Expect(peerCert.Subject).To(Equal("CN=www.example.org,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US"))
	t.Expect(peerCert.Issuer).To(Equal("CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US"))
	t.Expect(peerCert.NotBefore.Undefined()).To(BeFalse())
	t.Expect(peerCert.NotBefore.IsRel).To(BeFalse())
	t.Expect(peerCert.NotAfter.Undefined()).To(BeFalse())
	t.Expect(peerCert.NotAfter.IsRel).To(BeFalse())
	t.Expect(peerCert.NotBefore.Abs.Before(time.Now())).To(BeTrue())
	t.Expect(peerCert.NotAfter.Abs.After(time.Now())).To(BeTrue())
	peerCert = tlsTun.PeerCerts[1]
	t.Expect(peerCert.IsCA).To(BeTrue())
	t.Expect(peerCert.Subject).To(Equal("CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US"))
	t.Expect(peerCert.Issuer).To(Equal("CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US"))
	t.Expect(peerCert.NotBefore.Undefined()).To(BeFalse())
	t.Expect(peerCert.NotBefore.IsRel).To(BeFalse())
	t.Expect(peerCert.NotAfter.Undefined()).To(BeFalse())
	t.Expect(peerCert.NotAfter.IsRel).To(BeFalse())
	t.Expect(peerCert.NotBefore.Abs.Before(time.Now())).To(BeTrue())
	t.Expect(peerCert.NotAfter.Abs.After(time.Now())).To(BeTrue())

	err = client.Close()
	t.Expect(err).ToNot(HaveOccurred())
}

// TestTLSCertErrors : test that even when TLS handshake fails due to a bad certificate,
// we still get the certificate issuer and the subject in the trace.
func TestTLSCertErrors(test *testing.T) {
	t := NewGomegaWithT(test)

	// Option required for TLS tracing.
	// WithLogging is not specified to test nilLogger.
	opts := []nettrace.TraceOpt{
		&nettrace.WithHTTPReqTrace{},
	}
	client, err := nettrace.NewHTTPClient(nettrace.HTTPClientCfg{
		PreferHTTP2: true,
		ReqTimeout:  5 * time.Second,
	}, opts...)
	t.Expect(err).ToNot(HaveOccurred())

	// Expired certificate
	req, err := http.NewRequest("GET", "https://expired.badssl.com/", nil)
	t.Expect(err).ToNot(HaveOccurred())
	resp, err := client.Do(req)
	t.Expect(err).To(HaveOccurred())
	t.Expect(resp).To(BeNil())
	trace, _, err := client.GetTrace("expired cert")
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(trace.TLSTunnels).To(HaveLen(1))
	tlsTun := trace.TLSTunnels[0]
	t.Expect(tlsTun.HandshakeErr).ToNot(BeZero())
	t.Expect(tlsTun.PeerCerts).To(HaveLen(1)) // when TLS fails, we only get the problematic cert
	peerCert := tlsTun.PeerCerts[0]
	t.Expect(peerCert.IsCA).To(BeFalse())
	t.Expect(peerCert.Issuer).To(Equal("CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB"))
	t.Expect(peerCert.Subject).To(Equal("CN=*.badssl.com,OU=Domain Control Validated+OU=PositiveSSL Wildcard"))
	t.Expect(peerCert.NotBefore.Abs.IsZero()).To(BeFalse())
	t.Expect(peerCert.NotAfter.Abs.Before(time.Now())).To(BeTrue())
	err = client.ClearTrace()
	t.Expect(err).ToNot(HaveOccurred())

	// Wrong Host
	req, err = http.NewRequest("GET", "https://wrong.host.badssl.com/", nil)
	t.Expect(err).ToNot(HaveOccurred())
	resp, err = client.Do(req)
	t.Expect(err).To(HaveOccurred())
	t.Expect(resp).To(BeNil())
	trace, _, err = client.GetTrace("wrong host")
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(trace.TLSTunnels).To(HaveLen(1))
	tlsTun = trace.TLSTunnels[0]
	t.Expect(tlsTun.HandshakeErr).ToNot(BeZero())
	t.Expect(tlsTun.PeerCerts).To(HaveLen(1))
	peerCert = tlsTun.PeerCerts[0]
	t.Expect(peerCert.IsCA).To(BeFalse())
	t.Expect(peerCert.Issuer).To(Equal("CN=R3,O=Let's Encrypt,C=US"))
	t.Expect(peerCert.Subject).To(Equal("CN=*.badssl.com"))
	t.Expect(peerCert.NotBefore.Abs.Before(time.Now())).To(BeTrue())
	t.Expect(peerCert.NotAfter.Abs.After(time.Now())).To(BeTrue())
	err = client.ClearTrace()
	t.Expect(err).ToNot(HaveOccurred())

	// Untrusted root
	req, err = http.NewRequest("GET", "https://untrusted-root.badssl.com/", nil)
	t.Expect(err).ToNot(HaveOccurred())
	resp, err = client.Do(req)
	t.Expect(err).To(HaveOccurred())
	t.Expect(resp).To(BeNil())
	trace, _, err = client.GetTrace("untrusted root")
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(trace.TLSTunnels).To(HaveLen(1))
	tlsTun = trace.TLSTunnels[0]
	t.Expect(tlsTun.HandshakeErr).ToNot(BeZero())
	t.Expect(tlsTun.PeerCerts).To(HaveLen(1))
	peerCert = tlsTun.PeerCerts[0]
	t.Expect(peerCert.IsCA).To(BeTrue())
	t.Expect(peerCert.Issuer).To(Equal("CN=BadSSL Untrusted Root Certificate Authority,O=BadSSL,L=San Francisco,ST=California,C=US"))
	t.Expect(peerCert.Subject).To(Equal("CN=BadSSL Untrusted Root Certificate Authority,O=BadSSL,L=San Francisco,ST=California,C=US"))
	t.Expect(peerCert.NotBefore.Abs.Before(time.Now())).To(BeTrue())
	t.Expect(peerCert.NotAfter.Abs.After(time.Now())).To(BeTrue())
	err = client.ClearTrace()
	t.Expect(err).ToNot(HaveOccurred())

	err = client.Close()
	t.Expect(err).ToNot(HaveOccurred())
}

// Trace HTTP request targeted at a non-existent host name.
func TestNonExistentHost(test *testing.T) {
	t := NewGomegaWithT(test)

	// Options that do not require administrative privileges.
	opts := []nettrace.TraceOpt{
		&nettrace.WithLogging{},
		&nettrace.WithHTTPReqTrace{
			HeaderFields: nettrace.HdrFieldsOptWithValues,
		},
		&nettrace.WithSockTrace{},
		&nettrace.WithDNSQueryTrace{},
	}
	client, err := nettrace.NewHTTPClient(nettrace.HTTPClientCfg{
		ReqTimeout: 5 * time.Second,
	}, opts...)
	t.Expect(err).ToNot(HaveOccurred())

	req, err := http.NewRequest("GET", "https://non-existent-host.com", nil)
	t.Expect(err).ToNot(HaveOccurred())
	resp, err := client.Do(req)
	t.Expect(err).To(HaveOccurred())
	t.Expect(resp).To(BeNil())
	trace, _, err := client.GetTrace("non-existent host")
	t.Expect(err).ToNot(HaveOccurred())
	traceBeginAsRel := nettrace.Timestamp{IsRel: true, Rel: 0}

	// Dial trace
	t.Expect(trace.Dials).To(HaveLen(1)) // one failed Dial (DNS failed)
	dial := trace.Dials[0]
	t.Expect(dial.TraceID).ToNot(BeZero())
	relTimeIsInBetween(t, dial.DialBeginAt, traceBeginAsRel, trace.TraceEndAt)
	relTimeIsInBetween(t, dial.DialEndAt, dial.DialBeginAt, trace.TraceEndAt)
	t.Expect(dial.DstAddress).To(Equal("non-existent-host.com:443"))
	t.Expect(dial.ResolverDials).ToNot(BeEmpty())
	for _, resolvDial := range dial.ResolverDials {
		relTimeIsInBetween(t, resolvDial.DialBeginAt, dial.DialBeginAt, dial.DialEndAt)
		relTimeIsInBetween(t, resolvDial.DialEndAt, resolvDial.DialBeginAt, dial.DialEndAt)
		t.Expect(resolvDial.Nameserver).ToNot(BeZero())
		if !resolvDial.EstablishedConn.Undefined() {
			t.Expect(resolvDial.DialErr).To(BeZero())
			t.Expect(trace.UDPConns.Get(resolvDial.EstablishedConn)).ToNot(BeNil())
		}
	}
	t.Expect(dial.DialErr).ToNot(BeZero())
	t.Expect(dial.EstablishedConn).To(BeZero())

	// DNS trace
	t.Expect(trace.DNSQueries).ToNot(BeEmpty())
	for _, dnsQuery := range trace.DNSQueries {
		t.Expect(dnsQuery.FromDial == dial.TraceID).To(BeTrue())
		t.Expect(dnsQuery.TraceID).ToNot(BeZero())
		udpConn := trace.UDPConns.Get(dnsQuery.Connection)
		t.Expect(udpConn).ToNot(BeNil())

		t.Expect(dnsQuery.DNSQueryMsgs).To(HaveLen(1))
		dnsMsg := dnsQuery.DNSQueryMsgs[0]
		relTimeIsInBetween(t, dnsMsg.SentAt, udpConn.SocketCreateAt, udpConn.ConnCloseAt)
		t.Expect(dnsMsg.Questions).To(HaveLen(1))
		t.Expect(dnsMsg.Questions[0].Name).To(HavePrefix("non-existent-host.com."))
		t.Expect(dnsMsg.Questions[0].Type).To(Or(
			Equal(nettrace.DNSResTypeA), Equal(nettrace.DNSResTypeAAAA)))
		t.Expect(dnsMsg.Truncated).To(BeFalse())

		t.Expect(dnsQuery.DNSReplyMsgs).To(HaveLen(1))
		dnsReply := dnsQuery.DNSReplyMsgs[0]
		relTimeIsInBetween(t, dnsReply.RecvAt, dnsMsg.SentAt, udpConn.ConnCloseAt)
		t.Expect(dnsReply.ID == dnsMsg.ID).To(BeTrue())
		t.Expect(dnsReply.RCode).To(Equal(nettrace.DNSRCodeNXDomain))
		t.Expect(dnsReply.Answers).To(BeEmpty())
		t.Expect(dnsReply.Truncated).To(BeFalse())
	}

	// UDP connection trace
	t.Expect(trace.UDPConns).ToNot(BeEmpty())
	for _, udpConn := range trace.UDPConns {
		t.Expect(udpConn.TraceID).ToNot(BeZero())
		t.Expect(udpConn.FromDial == dial.TraceID).To(BeTrue())
		relTimeIsInBetween(t, udpConn.SocketCreateAt, dial.DialBeginAt, dial.DialEndAt)
		relTimeIsInBetween(t, udpConn.ConnCloseAt, udpConn.SocketCreateAt, dial.DialEndAt)
		t.Expect(net.ParseIP(udpConn.AddrTuple.SrcIP)).ToNot(BeNil())
		t.Expect(net.ParseIP(udpConn.AddrTuple.DstIP)).ToNot(BeNil())
		t.Expect(udpConn.AddrTuple.SrcPort).ToNot(BeZero())
		t.Expect(udpConn.AddrTuple.DstPort).ToNot(BeZero())
		t.Expect(udpConn.SocketTrace).ToNot(BeNil())
		t.Expect(udpConn.SocketTrace.SocketOps).ToNot(BeEmpty())
		for _, socketOp := range udpConn.SocketTrace.SocketOps {
			relTimeIsInBetween(t, socketOp.CallAt, udpConn.SocketCreateAt, udpConn.ConnCloseAt)
			relTimeIsInBetween(t, socketOp.ReturnAt, socketOp.CallAt, udpConn.ConnCloseAt)
		}
		t.Expect(udpConn.Conntract).To(BeNil()) // WithConntrack requires root privileges
		t.Expect(udpConn.TotalRecvBytes).ToNot(BeZero())
		t.Expect(udpConn.TotalSentBytes).ToNot(BeZero())
	}

	// TCP connection trace
	t.Expect(trace.TCPConns).To(BeEmpty())

	// TLS tunnel trace
	t.Expect(trace.TLSTunnels).To(BeEmpty())

	// HTTP request trace
	t.Expect(trace.HTTPRequests).To(HaveLen(1))
	httpReq := trace.HTTPRequests[0]
	t.Expect(httpReq.TraceID).ToNot(BeZero())
	t.Expect(httpReq.TCPConn).To(BeZero())
	t.Expect(httpReq.ProtoMajor).To(BeEquivalentTo(1))
	t.Expect(httpReq.ProtoMinor).To(BeEquivalentTo(1))
	relTimeIsInBetween(t, httpReq.ReqSentAt, traceBeginAsRel, trace.TraceEndAt)
	t.Expect(httpReq.ReqError).ToNot(BeZero())
	t.Expect(httpReq.ReqMethod).To(Equal("GET"))
	t.Expect(httpReq.ReqURL).To(Equal("https://non-existent-host.com"))
	t.Expect(httpReq.ReqHeader).To(BeEmpty())
	t.Expect(httpReq.ReqContentLen).To(BeZero())
	t.Expect(httpReq.RespRecvAt.Undefined()).To(BeTrue())
	t.Expect(httpReq.RespStatusCode).To(BeZero())
	t.Expect(httpReq.RespHeader).To(BeEmpty())
	t.Expect(httpReq.RespContentLen).To(BeZero())

	err = client.Close()
	t.Expect(err).ToNot(HaveOccurred())
}

// Trace HTTP request targeted at a non-responsive destination (nobody is listening).
func TestUnresponsiveDest(test *testing.T) {
	t := NewGomegaWithT(test)

	// Options that do not require administrative privileges.
	opts := []nettrace.TraceOpt{
		&nettrace.WithLogging{},
		&nettrace.WithHTTPReqTrace{
			HeaderFields: nettrace.HdrFieldsOptWithValues,
		},
		&nettrace.WithSockTrace{},
		&nettrace.WithDNSQueryTrace{},
	}
	client, err := nettrace.NewHTTPClient(nettrace.HTTPClientCfg{
		ReqTimeout: 5 * time.Second,
	}, opts...)
	t.Expect(err).ToNot(HaveOccurred())

	req, err := http.NewRequest("GET", "https://198.51.100.100", nil)
	t.Expect(err).ToNot(HaveOccurred())
	resp, err := client.Do(req)
	t.Expect(err).To(HaveOccurred())
	t.Expect(resp).To(BeNil())
	time.Sleep(time.Second)
	trace, _, err := client.GetTrace("unresponsive dest")
	t.Expect(err).ToNot(HaveOccurred())
	traceBeginAsRel := nettrace.Timestamp{IsRel: true, Rel: 0}

	// Dial trace
	t.Expect(trace.Dials).To(HaveLen(1)) // one failed Dial (DNS failed)
	dial := trace.Dials[0]
	t.Expect(dial.TraceID).ToNot(BeZero())
	relTimeIsInBetween(t, dial.DialBeginAt, traceBeginAsRel, trace.TraceEndAt)
	relTimeIsInBetween(t, dial.DialEndAt, dial.DialBeginAt, trace.TraceEndAt)
	relTimeIsInBetween(t, dial.CtxCloseAt, dial.DialBeginAt, trace.TraceEndAt)
	t.Expect(dial.DstAddress).To(Equal("198.51.100.100:443"))
	t.Expect(dial.ResolverDials).To(BeEmpty())
	t.Expect(dial.DialErr).ToNot(BeZero())
	t.Expect(dial.EstablishedConn).To(BeZero())

	// DNS trace
	t.Expect(trace.DNSQueries).To(BeEmpty())

	// UDP connection trace
	t.Expect(trace.UDPConns).To(BeEmpty())

	// TCP connection trace
	t.Expect(trace.TCPConns).To(HaveLen(1))
	tcpConn := trace.TCPConns[0]
	t.Expect(tcpConn.TraceID).ToNot(BeZero())
	t.Expect(tcpConn.FromDial == dial.TraceID).To(BeTrue())
	t.Expect(tcpConn.Reused).To(BeFalse())
	relTimeIsInBetween(t, tcpConn.HandshakeBeginAt, dial.DialBeginAt, dial.DialEndAt)
	// killed from outside of Dial
	relTimeIsInBetween(t, tcpConn.HandshakeEndAt, tcpConn.HandshakeBeginAt, trace.TraceEndAt)
	t.Expect(tcpConn.ConnCloseAt.Undefined()).To(BeTrue())
	t.Expect(net.ParseIP(tcpConn.AddrTuple.SrcIP)).ToNot(BeNil())
	t.Expect(net.ParseIP(tcpConn.AddrTuple.DstIP)).ToNot(BeNil())
	t.Expect(tcpConn.AddrTuple.SrcPort).ToNot(BeZero()) // btw. not easy to get when TLS handshake fails
	t.Expect(tcpConn.AddrTuple.DstPort).ToNot(BeZero())
	t.Expect(tcpConn.SocketTrace).To(BeZero())
	t.Expect(tcpConn.Conntract).To(BeNil())
	t.Expect(tcpConn.TotalRecvBytes).To(BeZero())
	t.Expect(tcpConn.TotalSentBytes).To(BeZero())

	// TLS tunnel trace
	t.Expect(trace.TLSTunnels).To(BeEmpty())

	// HTTP request trace
	t.Expect(trace.HTTPRequests).To(HaveLen(1))
	httpReq := trace.HTTPRequests[0]
	t.Expect(httpReq.TraceID).ToNot(BeZero())
	t.Expect(httpReq.TCPConn).To(BeZero())
	t.Expect(httpReq.ProtoMajor).To(BeEquivalentTo(1))
	t.Expect(httpReq.ProtoMinor).To(BeEquivalentTo(1))
	relTimeIsInBetween(t, httpReq.ReqSentAt, traceBeginAsRel, trace.TraceEndAt)
	t.Expect(httpReq.ReqError).ToNot(BeZero())
	t.Expect(httpReq.ReqMethod).To(Equal("GET"))
	t.Expect(httpReq.ReqURL).To(Equal("https://198.51.100.100"))
	t.Expect(httpReq.ReqHeader).To(BeEmpty())
	t.Expect(httpReq.ReqContentLen).To(BeZero())
	t.Expect(httpReq.RespRecvAt.Undefined()).To(BeTrue())
	t.Expect(httpReq.RespStatusCode).To(BeZero())
	t.Expect(httpReq.RespHeader).To(BeEmpty())
	t.Expect(httpReq.RespContentLen).To(BeZero())

	err = client.Close()
	t.Expect(err).ToNot(HaveOccurred())
}

func TestReusedTCPConn(test *testing.T) {
	t := NewWithT(test)

	// Options that do not require administrative privileges.
	opts := []nettrace.TraceOpt{
		&nettrace.WithLogging{},
		&nettrace.WithHTTPReqTrace{
			HeaderFields: nettrace.HdrFieldsOptWithValues,
		},
		&nettrace.WithSockTrace{},
		&nettrace.WithDNSQueryTrace{},
	}
	client, err := nettrace.NewHTTPClient(nettrace.HTTPClientCfg{
		DisableKeepAlive: false, // allow TCP conn to be reused between HTTP requests
	}, opts...)
	t.Expect(err).ToNot(HaveOccurred())

	// First GET request
	req, err := http.NewRequest("GET", "https://www.example.com", nil)
	t.Expect(err).ToNot(HaveOccurred())
	resp, err := client.Do(req)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(resp).ToNot(BeNil())
	t.Expect(resp.StatusCode).To(Equal(200))
	t.Expect(resp.Body).ToNot(BeNil())
	body := new(strings.Builder)
	_, err = io.Copy(body, resp.Body)
	t.Expect(err).ToNot(HaveOccurred())
	err = resp.Body.Close()
	t.Expect(err).ToNot(HaveOccurred())

	trace, _, err := client.GetTrace("GET www.example.com over HTTPS for the first time")
	t.Expect(err).ToNot(HaveOccurred())

	// Dial trace
	t.Expect(trace.Dials).To(HaveLen(1)) // no redirects
	dial := trace.Dials[0]
	t.Expect(dial.TraceID).ToNot(BeZero())
	t.Expect(dial.DstAddress).To(Equal("www.example.com:443"))

	// HTTP request trace
	t.Expect(trace.HTTPRequests).To(HaveLen(1))
	httpReq := trace.HTTPRequests[0]
	t.Expect(httpReq.TraceID).ToNot(BeZero())
	t.Expect(httpReq.TCPConn.Undefined()).To(BeFalse())
	usedTCPConn := trace.TCPConns.Get(httpReq.TCPConn)
	t.Expect(usedTCPConn).ToNot(BeNil())
	t.Expect(usedTCPConn.FromDial == dial.TraceID).To(BeTrue())
	t.Expect(usedTCPConn.Reused).To(BeFalse())
	t.Expect(usedTCPConn.ConnCloseAt.Undefined()).To(BeTrue())
	t.Expect(usedTCPConn.TotalRecvBytes).ToNot(BeZero())
	t.Expect(usedTCPConn.TotalSentBytes).ToNot(BeZero())

	// TLS tunnel trace.
	t.Expect(trace.TLSTunnels).To(HaveLen(1))
	tlsTun := trace.TLSTunnels[0]
	t.Expect(tlsTun.TraceID).ToNot(BeZero())
	t.Expect(tlsTun.TCPConn == usedTCPConn.TraceID).To(BeTrue())

	// Idle TCP connection should not be removed from the trace
	err = client.ClearTrace()
	t.Expect(err).ToNot(HaveOccurred())

	// Second request to the same destination
	req, err = http.NewRequest("GET", "https://www.example.com", nil)
	t.Expect(err).ToNot(HaveOccurred())
	resp, err = client.Do(req)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(resp).ToNot(BeNil())
	t.Expect(resp.StatusCode).To(Equal(200))
	t.Expect(resp.Body).ToNot(BeNil())
	body = new(strings.Builder)
	_, err = io.Copy(body, resp.Body)
	t.Expect(err).ToNot(HaveOccurred())
	err = resp.Body.Close()
	t.Expect(err).ToNot(HaveOccurred())

	trace, _, err = client.GetTrace("GET www.example.com over HTTPS for the second time")
	t.Expect(err).ToNot(HaveOccurred())
	traceBeginAsRel := nettrace.Timestamp{IsRel: true, Rel: 0}

	// No dialing this time - connection is reused.
	t.Expect(trace.Dials).To(BeEmpty())
	t.Expect(trace.DNSQueries).To(BeEmpty())
	t.Expect(trace.UDPConns).To(BeEmpty())
	t.Expect(trace.TLSTunnels).To(BeEmpty())

	// HTTP request trace
	t.Expect(trace.HTTPRequests).To(HaveLen(1))
	httpReq = trace.HTTPRequests[0]
	t.Expect(httpReq.TraceID).ToNot(BeZero())
	t.Expect(httpReq.TCPConn == usedTCPConn.TraceID).To(BeTrue())
	t.Expect(httpReq.ProtoMajor).To(BeEquivalentTo(1))
	t.Expect(httpReq.ProtoMinor).To(BeEquivalentTo(1))
	t.Expect(httpReq.NetworkProxy).To(BeZero())
	relTimeIsInBetween(t, httpReq.ReqSentAt, traceBeginAsRel, trace.TraceEndAt)
	t.Expect(httpReq.ReqError).To(BeZero())
	t.Expect(httpReq.ReqMethod).To(Equal("GET"))
	t.Expect(httpReq.ReqURL).To(Equal("https://www.example.com"))
	t.Expect(httpReq.ReqHeader).To(BeEmpty())
	t.Expect(httpReq.ReqContentLen).To(BeZero())
	relTimeIsInBetween(t, httpReq.RespRecvAt, httpReq.ReqSentAt, trace.TraceEndAt)
	t.Expect(httpReq.RespStatusCode).To(Equal(200))
	t.Expect(httpReq.RespHeader).ToNot(BeEmpty())
	contentType := httpReq.RespHeader.Get("content-type")
	t.Expect(contentType).ToNot(BeNil())
	t.Expect(contentType.FieldVal).To(ContainSubstring("text/html"))
	t.Expect(contentType.FieldValLen).To(BeEquivalentTo(len(contentType.FieldVal)))
	t.Expect(httpReq.RespContentLen).ToNot(BeZero())

	// Reused TCP connection trace
	usedTCPConn = trace.TCPConns.Get(usedTCPConn.TraceID)
	t.Expect(usedTCPConn).ToNot(BeNil())
	t.Expect(usedTCPConn.FromDial == dial.TraceID).To(BeTrue())
	t.Expect(usedTCPConn.Reused).To(BeTrue())
	t.Expect(usedTCPConn.HandshakeBeginAt.IsRel).To(BeFalse())
	t.Expect(usedTCPConn.HandshakeEndAt.IsRel).To(BeFalse())
	t.Expect(usedTCPConn.HandshakeBeginAt.Abs.Before(usedTCPConn.HandshakeEndAt.Abs)).To(BeTrue())
	t.Expect(usedTCPConn.HandshakeEndAt.Abs.Before(trace.TraceBeginAt.Abs)).To(BeTrue())
	t.Expect(usedTCPConn.ConnCloseAt.Undefined()).To(BeTrue())
	t.Expect(usedTCPConn.TotalRecvBytes).ToNot(BeZero())
	t.Expect(usedTCPConn.TotalSentBytes).ToNot(BeZero())

	err = client.Close()
	t.Expect(err).ToNot(HaveOccurred())
}

func TestAllNameserversSkipped(test *testing.T) {
	t := NewWithT(test)

	opts := []nettrace.TraceOpt{
		&nettrace.WithHTTPReqTrace{},
		&nettrace.WithDNSQueryTrace{},
	}
	client, err := nettrace.NewHTTPClient(nettrace.HTTPClientCfg{
		SkipNameserver: func(ipAddr net.IP, port uint16) (skip bool, reason string) {
			return true, "skipping any configured nameserver"
		},
	}, opts...)
	t.Expect(err).ToNot(HaveOccurred())

	req, err := http.NewRequest("GET", "https://www.example.com", nil)
	t.Expect(err).ToNot(HaveOccurred())
	resp, err := client.Do(req)
	t.Expect(err).To(HaveOccurred())
	t.Expect(resp).To(BeNil())

	trace, _, err := client.GetTrace("GET www.example.com but skip all nameservers")
	t.Expect(err).ToNot(HaveOccurred())

	// Dial trace
	t.Expect(trace.Dials).To(HaveLen(1))
	dial := trace.Dials[0]
	t.Expect(dial.TraceID).ToNot(BeZero())
	t.Expect(dial.DstAddress).To(Equal("www.example.com:443"))
	t.Expect(dial.DialErr).To(ContainSubstring("skipping any configured nameserver"))
	t.Expect(dial.ResolverDials).To(BeEmpty())
	t.Expect(dial.SkippedNameservers).ToNot(BeEmpty())

	t.Expect(trace.DNSQueries).To(BeEmpty())
	t.Expect(trace.UDPConns).To(BeEmpty())
	t.Expect(trace.TCPConns).To(BeEmpty())
	t.Expect(trace.TLSTunnels).To(BeEmpty())

	t.Expect(trace.HTTPRequests).To(HaveLen(1))
	httpReq := trace.HTTPRequests[0]
	t.Expect(httpReq.TraceID).ToNot(BeZero())
	t.Expect(httpReq.TCPConn.Undefined()).To(BeTrue())
	t.Expect(httpReq.ReqMethod).To(Equal("GET"))
	t.Expect(httpReq.ReqURL).To(Equal("https://www.example.com"))
	t.Expect(httpReq.ReqError).To(ContainSubstring("skipping any configured nameserver"))

	err = client.Close()
	t.Expect(err).ToNot(HaveOccurred())
}
