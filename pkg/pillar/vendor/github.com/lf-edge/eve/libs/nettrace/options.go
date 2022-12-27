// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nettrace

import (
	"fmt"
	"os"
)

// TraceOpt allows to customize tracing of network events.
type TraceOpt interface {
	isTraceOpt()
}

// TraceOptWithDefaults is implemented by options that have some non-zero default values.
type TraceOptWithDefaults interface {
	TraceOpt
	setDefaults()
}

// WithLogging : enable logging inside the network tracing engine.
// When enabled then by default Logrus from Sirupsen will be used
// (see github.com/sirupsen/logrus), but a custom logger can be provided instead.
type WithLogging struct {
	CustomLogger Logger
}

func (o *WithLogging) isTraceOpt() {}

// Logger is used to log noteworthy events happening inside the network tracing engine.
type Logger interface {
	// Tracef : formatted log message with info useful for finer-grained debugging.
	Tracef(format string, args ...interface{})
	// Debugf : formatted log message with info useful for debugging.
	Debugf(format string, args ...interface{})
	// Infof : formatted log message with a general info about what's going on
	// inside the application.
	Infof(format string, args ...interface{})
	// Warningf : formatted log message with a warning.
	Warningf(format string, args ...interface{})
	// Errorf : formatted log message with an error.
	Errorf(format string, args ...interface{})
	// Fatalf : formatted log message with an error, ending with a call to os.Exit()
	// with a non-zero return value.
	Fatalf(format string, args ...interface{})
	// Panicf : formatted log message with an error, raising a panic.
	Panicf(format string, args ...interface{})
}

// nilLogger is used internally when logging should be disabled.
type nilLogger struct{}

// Tracef does nothing here.
func (sl *nilLogger) Tracef(format string, args ...interface{}) {}

// Debugf does nothing here.
func (sl *nilLogger) Debugf(format string, args ...interface{}) {}

// Infof does nothing here.
func (sl *nilLogger) Infof(format string, args ...interface{}) {}

// Warningf does nothing here.
func (sl *nilLogger) Warningf(format string, args ...interface{}) {}

// Errorf does nothing here.
func (sl *nilLogger) Errorf(format string, args ...interface{}) {}

// Fatalf exits the application without logging anything.
func (sl *nilLogger) Fatalf(format string, args ...interface{}) {
	os.Exit(1)
}

// Panicf raises the panic without logging anything.
func (sl *nilLogger) Panicf(format string, args ...interface{}) {
	panic(fmt.Sprintf(format, args...))
}

// WithConntrack : obtain and include conntrack entries (provided by netfilter)
// inside the networkTrace records of TCP and UDP connections (TCPConnTrace.Conntrack
// and UDPConnTrace.Conntrack).
type WithConntrack struct {
}

func (o *WithConntrack) isTraceOpt() {}

// WithSockTrace : record read/write operations performed over AF_INET sockets
// of traced TCP and UDP connections (stored under TCPConnTrace.SocketTrace and
// UDPConnTrace.SocketTrace).
type WithSockTrace struct {
}

func (o *WithSockTrace) isTraceOpt() {}

// WithDNSQueryTrace : enable tracing of DNS queries and their responses (requires
// to parse DNS messages sent over a socket).
// DNSQueryTrace-s are stored under NetTrace.DNSQueries.
type WithDNSQueryTrace struct {
}

func (o *WithDNSQueryTrace) isTraceOpt() {}

// WithHTTPReqTrace : enable tracing of HTTP requests and their responses.
// This requires to put a custom RoundTripper implementation under
// http.Client.Transport. However, some libraries that take HTTP client
// as an argument may expect that Transport is of type http.Transport (the standard
// implementation). In such cases, it is necessary to disable HTTP request tracing.
// As an unfortunate side effect, HTTPTrace returned by HTTPClient will also miss
// TLSTunnels, which it has no way of capturing them anymore.
type WithHTTPReqTrace struct {
	// HeaderFields : specify how HTTP header fields should be recorded.
	HeaderFields HdrFieldsOpt
	// ExcludeHeaderField is a callback that can be optionally specified to filter
	// out some HTTP header fields from being recorded (by returning true).
	ExcludeHeaderField func(key string) bool
}

// HdrFieldsOpt : options for capturing of HTTP header fields.
type HdrFieldsOpt uint8

const (
	// HdrFieldsOptDisabled : do not capture and include HTTP header fields
	// in HTTPReqTrace (may contain sensitive data).
	HdrFieldsOptDisabled HdrFieldsOpt = iota
	// HdrFieldsOptNamesOnly : record only header field names without values
	// and their length.
	// ExcludeHeaderField may still be used to completely filter out some header
	// fields.
	HdrFieldsOptNamesOnly
	// HdrFieldsOptValueLenOnly : for each header field record the name and
	// the value length, but not the value itself.
	// ExcludeHeaderField may still be used to completely filter out some header
	// fields.
	HdrFieldsOptValueLenOnly
	// HdrFieldsOptWithValues : record every header field including values.
	// ExcludeHeaderField may still be used to completely filter out some header
	// fields.
	HdrFieldsOptWithValues
)

func (o *WithHTTPReqTrace) isTraceOpt() {}

const (
	// By default, capture at most 1518 of every packet (common MTU + ethernet header size).
	defaultPcapSnapLen = 1518
	// De default, limit the total size of pcap to 1 MiB.
	defaultPcapMaxTotalSize = 1 << 20
)

// WithPacketCapture : run packet capture on selected interfaces (in both directions).
// Captured packets are typically filtered to contain only those that correspond
// to traced connections.
// Packet capture is returned as PacketCapture - one per each interface.
type WithPacketCapture struct {
	// Interfaces to capture packets from.
	Interfaces []string
	// PacketSnaplen : maximum size in bytes to read for each packet.
	// Larger packets will be (silently) returned truncated.
	// Default snaplen is 1518 bytes.
	PacketSnaplen uint32
	// TotalSizeLimit : total limit in bytes for all captured packets.
	// Once the limit is reached, further captured packets are dropped or the pcap process
	// is completely stopped/paused. To indicate that this happened, the returned
	// PacketCapture will have .Truncated set to true.
	// Default upper limit for pcap size is 1MiB.
	TotalSizeLimit uint32
	// IncludeICMP : if enabled, all sent/received ICMP packets will be captured as well.
	// This can be useful for troubleshooting purposes.
	IncludeICMP bool
	// IncludeARP : if enabled, all sent/received ARP packets will be captured as well.
	// This can be useful for troubleshooting purposes.
	IncludeARP bool
	// TCPWithoutPayload : if enabled, then for TCP only packets that do not carry any
	// payload will be captured. For example, this will include SYN, RST and FIN packets
	// as well as ACK packets without data piggybacking.
	TCPWithoutPayload bool
}

func (o *WithPacketCapture) isTraceOpt() {}

func (o *WithPacketCapture) setDefaults() {
	if o.PacketSnaplen == 0 {
		o.PacketSnaplen = defaultPcapSnapLen
	}
	if o.TotalSizeLimit == 0 {
		o.TotalSizeLimit = defaultPcapMaxTotalSize
	}
}
