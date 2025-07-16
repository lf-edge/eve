// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
	"github.com/lf-edge/eve/evetest/sdn/vm/cmd/goproxy/config"
	log "github.com/sirupsen/logrus"
)

func runTransparentProxy(proxyConfig config.ProxyConfig) {
	// Run HTTP proxy.
	httpPort := proxyConfig.HTTPPort.Port
	if httpPort != 0 {
		for _, listenIP := range proxyConfig.ListenIPs {
			httpProxy := newProxy(proxyConfig)
			installProxyHandlers(proxyConfig, false, true, httpProxy)
			proxyAddr := net.JoinHostPort(listenIP, fmt.Sprintf("%d", httpPort))
			go func(addr string, proxy *goproxy.ProxyHttpServer) {
				log.Fatalln(http.ListenAndServe(addr, proxy))
			}(proxyAddr, httpProxy)
		}
	}

	// Run HTTPS proxy(ies).
	for _, port := range proxyConfig.HTTPSPorts {
		for _, listenIP := range proxyConfig.ListenIPs {
			httpsProxy := newProxy(proxyConfig)
			installProxyHandlers(proxyConfig, true, true, httpsProxy)
			go func(ip string, port uint16, proxy *goproxy.ProxyHttpServer) {
				proxyAddr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
				listener, err := net.Listen("tcp", proxyAddr)
				if err != nil {
					log.Fatalf("Error listening for HTTPS connections: %v", err)
				}
				tproxyListener(listener, port, proxy)
			}(listenIP, uint16(port.GetPort()), httpsProxy)
		}
	}
}

func tproxyListener(listener net.Listener, port uint16, httpsProxy *goproxy.ProxyHttpServer) {
	for {
		// Listen to the TLS ClientHello but make it a CONNECT request instead.
		c, err := listener.Accept()
		if err != nil {
			log.Errorf("Error accepting new connection: %v", err)
			continue
		}
		go func(c net.Conn) {
			log.Debugf("Received TLS ClientHello request on port %d", port)
			tlsConn, err := vhost.TLS(c)
			if err != nil {
				log.Errorf("Error accepting new connection: %v", err)
			}
			if tlsConn.Host() == "" {
				log.Errorf("Cannot support non-SNI enabled clients")
				return
			}
			log.Debugf("Received HTTPS request for host %s on port %d",
				tlsConn.Host(), port)

			connectReq := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: tlsConn.Host(),
					Host:   net.JoinHostPort(tlsConn.Host(), strconv.Itoa(int(port))),
				},
				Host:       tlsConn.Host(),
				Header:     make(http.Header),
				RemoteAddr: c.RemoteAddr().String(),
			}
			resp := tproxyResponseWriter{tlsConn}
			httpsProxy.ServeHTTP(resp, connectReq)
		}(c)
	}
}

type tproxyResponseWriter struct {
	net.Conn
}

func (w tproxyResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (w tproxyResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return w.Conn.Write(buf)
}

func (w tproxyResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (w tproxyResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w, bufio.NewReadWriter(bufio.NewReader(w), bufio.NewWriter(w)), nil
}
