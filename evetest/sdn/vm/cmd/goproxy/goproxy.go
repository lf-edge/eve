// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/elazarl/goproxy"
	"github.com/lf-edge/eve/evetest/sdn/vm/cmd/goproxy/config"
	log "github.com/sirupsen/logrus"
)

const (
	authRealm = "Auth"
)

func newProxy(proxyConfig config.ProxyConfig) *goproxy.ProxyHttpServer {
	proxy := goproxy.NewProxyHttpServer()
	proxy.NonproxyHandler = nonProxyHandler(proxy)
	// Configure logging of proxied connections.
	proxy.Logger = log.StandardLogger()
	proxy.Verbose = proxyConfig.Verbose
	return proxy
}

func installCA(caCert, caKey string) error {
	goproxyCa, err := tls.X509KeyPair([]byte(caCert), []byte(caKey))
	if err != nil {
		return err
	}
	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		return err
	}
	goproxy.GoproxyCa = goproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{
		Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.MitmConnect = &goproxy.ConnectAction{
		Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{
		Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.RejectConnect = &goproxy.ConnectAction{
		Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	return nil
}

func main() {
	log.SetReportCaller(true)
	configFile := flag.String("c", "/etc/goproxy.conf", "proxy config file")
	flag.Parse()

	// Read and parse config file.
	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("failed to read config file %s: %v", *configFile, err)
	}
	var proxyConfig config.ProxyConfig
	if err = json.Unmarshal(configBytes, &proxyConfig); err != nil {
		log.Fatalf("failed to unmarshal proxy config: %v", err)
	}

	// Process proxy config.
	if proxyConfig.LogFile != "" {
		logFile, err := os.OpenFile(proxyConfig.LogFile, os.O_WRONLY|os.O_CREATE, 0755)
		if err != nil {
			log.Fatalf("failed to open log file %s: %v", proxyConfig.LogFile, err)
		}
		log.SetOutput(logFile)
	}
	if proxyConfig.Verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	if proxyConfig.PidFile != "" {
		pidBytes := []byte(fmt.Sprintf("%d", os.Getpid()))
		err = os.WriteFile(proxyConfig.PidFile, pidBytes, 0664)
		if err != nil {
			log.Fatalf("failed to write PID file %s: %v", proxyConfig.PidFile, err)
		}
		defer os.Remove(proxyConfig.PidFile)
	}
	if proxyConfig.CACertPEM != "" {
		log.Infof("Installing CA cert and key")
		if err = installCA(proxyConfig.CACertPEM, proxyConfig.CAKeyPEM); err != nil {
			log.Fatal(err)
		}
	}

	// Run HTTP and HTTPS proxies.
	if proxyConfig.Transparent {
		runTransparentProxy(proxyConfig)
	} else {
		runExplicitProxy(proxyConfig)
	}

	cancelChan := make(chan os.Signal, 1)
	// Catch termination or interrupt signal.
	signal.Notify(cancelChan, syscall.SIGTERM, syscall.SIGINT)
	sig := <-cancelChan
	log.Infof("Caught terimation/interrupt signal: %v, exiting...", sig)
}
