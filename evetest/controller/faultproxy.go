// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// devAPIPathPrefix is the path prefix of the API the device talks to. A fault
// rule can only ever match a request below it, so that the admin API - which
// the test harness itself uses to read what the controller knows - can never be
// disturbed by an injected fault.
const devAPIPathPrefix = "/api/v2/edgedevice/"

// FaultAction says what the proxy does with a device request a rule matched.
type FaultAction int

const (
	// FaultActionStatus answers the request with a chosen status code without
	// passing it to the controller.
	FaultActionStatus FaultAction = iota
	// FaultActionCloseConn drops the connection without answering at all, which
	// the device sees as a failure to reach the controller rather than as an
	// answer from it.
	FaultActionCloseConn
	// FaultActionDelay passes the request to the controller, but only after
	// waiting, to exercise slow answers and request timeouts.
	FaultActionDelay
)

// FaultRule describes which device requests to interfere with, and how.
type FaultRule struct {
	// Method to match, e.g. "POST". Empty matches any method.
	Method string
	// PathSuffix matches the end of the request path, e.g. "/info" or
	// "/config". Empty matches any path below the device API.
	PathSuffix string
	// Action to take on a matching request.
	Action FaultAction
	// StatusCode to answer with, for FaultActionStatus.
	StatusCode int
	// Delay to wait for, for FaultActionDelay.
	Delay time.Duration
	// Count is how many matching requests the rule applies to. Zero means it
	// applies until cleared.
	Count int

	// matched counts how many requests the rule has been applied to so far.
	matched int
}

// matches tells whether the rule applies to the given request, without
// accounting for how many times it has already been used.
func (r *FaultRule) matches(req *http.Request) bool {
	if r.Method != "" && !strings.EqualFold(r.Method, req.Method) {
		return false
	}
	if !strings.HasPrefix(req.URL.Path, devAPIPathPrefix) {
		return false
	}
	return r.PathSuffix == "" || strings.HasSuffix(req.URL.Path, r.PathSuffix)
}

// FaultProxy sits between the edge devices and the controller and can be told
// to answer, delay or drop selected device requests, so that a test can see how
// EVE reacts to a controller which fails in a particular way. With no rules
// armed it forwards everything unchanged.
type FaultProxy struct {
	log         *logrus.Entry
	listenIPs   []net.IP
	listenPort  uint16
	certFile    string
	keyFile     string
	upstream    *url.URL
	upstreamCAs *x509.CertPool
	// upstreamName is the name the upstream certificate is verified against.
	upstreamName string

	lock    sync.Mutex
	rules   []*FaultRule
	servers []*http.Server
}

// NewFaultProxy creates a proxy which terminates TLS for the device-facing
// endpoint using the controller's own certificate, and forwards to the
// controller over a verified TLS connection.
func NewFaultProxy(log *logrus.Entry, listenIPs []net.IP, listenPort uint16,
	certFile, keyFile string, upstreamAddr string, upstreamName string,
	upstreamCAs *x509.CertPool) *FaultProxy {
	return &FaultProxy{
		log:        log,
		listenIPs:  listenIPs,
		listenPort: listenPort,
		certFile:   certFile,
		keyFile:    keyFile,
		upstream: &url.URL{
			Scheme: "https",
			Host:   upstreamAddr,
		},
		upstreamCAs:  upstreamCAs,
		upstreamName: upstreamName,
	}
}

// Start begins serving on every configured address.
func (p *FaultProxy) Start() error {
	cert, err := tls.LoadX509KeyPair(p.certFile, p.keyFile)
	if err != nil {
		return fmt.Errorf("fault proxy: failed to load controller cert: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(p.upstream)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    p.upstreamCAs,
			ServerName: p.upstreamName,
			MinVersion: tls.VersionTLS12,
		},
	}
	// Answers are relayed as they arrive; some of the controller API streams.
	proxy.FlushInterval = -1
	proxy.ErrorLog = nil

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if rule := p.takeRule(req); rule != nil {
			p.applyRule(rule, w, req, proxy)
			return
		}
		proxy.ServeHTTP(w, req)
	})

	for _, ip := range p.listenIPs {
		addr := net.JoinHostPort(ip.String(), fmt.Sprint(p.listenPort))
		listener, err := tls.Listen("tcp", addr, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
		if err != nil {
			p.stopServers()
			return fmt.Errorf("fault proxy: failed to listen on %s: %w", addr, err)
		}
		server := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 30 * time.Second,
		}
		p.lock.Lock()
		p.servers = append(p.servers, server)
		p.lock.Unlock()
		go func(l net.Listener) {
			if err := server.Serve(l); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				p.log.Warnf("fault proxy stopped serving: %v", err)
			}
		}(listener)
		p.log.Infof("Fault proxy listening on %s, forwarding to %s",
			addr, p.upstream.Host)
	}
	return nil
}

// Stop shuts the proxy down.
func (p *FaultProxy) Stop() {
	p.stopServers()
}

func (p *FaultProxy) stopServers() {
	p.lock.Lock()
	servers := p.servers
	p.servers = nil
	p.lock.Unlock()
	for _, server := range servers {
		_ = server.Close()
	}
}

// ArmFault adds a rule. Rules are consulted in the order they were added, and
// the first one still applicable to a request wins.
func (p *FaultProxy) ArmFault(rule FaultRule) {
	p.lock.Lock()
	defer p.lock.Unlock()
	copied := rule
	p.rules = append(p.rules, &copied)
	p.log.Infof("Armed controller fault: %+v", rule)
}

// ClearFaults removes every rule, so that the proxy forwards everything again.
func (p *FaultProxy) ClearFaults() {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.rules = nil
	p.log.Info("Cleared controller faults")
}

// takeRule returns the rule to apply to the request, counting the use against
// the rule's own limit.
func (p *FaultProxy) takeRule(req *http.Request) *FaultRule {
	p.lock.Lock()
	defer p.lock.Unlock()
	for _, rule := range p.rules {
		if rule.Count > 0 && rule.matched >= rule.Count {
			continue
		}
		if rule.matches(req) {
			rule.matched++
			return rule
		}
	}
	return nil
}

func (p *FaultProxy) applyRule(rule *FaultRule, w http.ResponseWriter,
	req *http.Request, proxy *httputil.ReverseProxy) {
	switch rule.Action {
	case FaultActionStatus:
		p.log.Infof("Fault proxy: answering %s %s with %d",
			req.Method, req.URL.Path, rule.StatusCode)
		w.WriteHeader(rule.StatusCode)

	case FaultActionCloseConn:
		p.log.Infof("Fault proxy: dropping the connection for %s %s",
			req.Method, req.URL.Path)
		// Aborts the response and closes the connection, whatever the protocol
		// version, without the server logging a stack trace for it.
		panic(http.ErrAbortHandler)

	case FaultActionDelay:
		p.log.Infof("Fault proxy: delaying %s %s by %v",
			req.Method, req.URL.Path, rule.Delay)
		select {
		case <-time.After(rule.Delay):
		case <-req.Context().Done():
			return
		}
		proxy.ServeHTTP(w, req)
	}
}
