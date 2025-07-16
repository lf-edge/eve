// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/sdn/vm/cmd/httpsrv/config"
	log "github.com/sirupsen/logrus"
)

func handler(content *api.HTTPContent) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("Received request: %+v", r)
		w.Header().Add("Content-Type", content.GetContentType())
		_, err := w.Write([]byte(content.GetContent()))
		if err != nil {
			log.Errorf("Failed to write content for request %+v: %v", r, err)
		}
	}
}

func main() {
	log.SetReportCaller(true)
	configFile := flag.String("c", "/etc/httpsrv.conf", "HTTP server config file")
	flag.Parse()

	// Read and parse config file.
	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("failed to read config file %s: %v", *configFile, err)
	}
	var httpSrvConfig config.HTTPSrvConfig
	if err = json.Unmarshal(configBytes, &httpSrvConfig); err != nil {
		log.Fatalf("failed to unmarshal HTTP server config: %v", err)
	}

	// Process HTTP server config.
	if httpSrvConfig.LogFile != "" {
		logFile, err := os.OpenFile(httpSrvConfig.LogFile, os.O_WRONLY|os.O_CREATE, 0755)
		if err != nil {
			log.Fatalf("failed to open log file %s: %v", httpSrvConfig.LogFile, err)
		}
		log.SetOutput(logFile)
	}
	if httpSrvConfig.Verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	if httpSrvConfig.PidFile != "" {
		pidBytes := []byte(fmt.Sprintf("%d", os.Getpid()))
		err = os.WriteFile(httpSrvConfig.PidFile, pidBytes, 0664)
		if err != nil {
			log.Fatalf("failed to write PID file %s: %v", httpSrvConfig.PidFile, err)
		}
		defer os.Remove(httpSrvConfig.PidFile)
	}

	for path, content := range httpSrvConfig.Paths {
		http.HandleFunc(path, handler(content))
	}

	if httpSrvConfig.HTTPPort != 0 {
		for _, listenIP := range httpSrvConfig.ListenIPs {
			srvAddr := net.JoinHostPort(listenIP, fmt.Sprintf("%d", httpSrvConfig.HTTPPort))
			go func(addr string) {
				log.Debugf("HTTP server listening on %s", addr)
				log.Fatalln(http.ListenAndServe(addr, nil))
			}(srvAddr)
		}
	}

	if httpSrvConfig.HTTPSPort != 0 {
		certFile, err := os.CreateTemp("", "httpsrv-*.cert")
		if err != nil {
			log.Fatalf("failed to create temporary file for the certificate: %v", err)
		}
		keyFile, err := os.CreateTemp("", "httpsrv-*.key")
		if err != nil {
			log.Fatalf("failed to create temporary file for the key: %v", err)
		}
		defer func() {
			if err = os.Remove(certFile.Name()); err != nil {
				log.Warnf("failed to remove temporary file %s: %v", certFile.Name(), err)
			}
			if err = os.Remove(keyFile.Name()); err != nil {
				log.Warnf("failed to remove temporary file %s: %v", keyFile.Name(), err)
			}
		}()
		if _, err = certFile.WriteString(httpSrvConfig.CertPEM); err != nil {
			log.Fatalf("failed to write server cert to file %s: %v", certFile.Name(), err)
		}
		if _, err = keyFile.WriteString(httpSrvConfig.KeyPEM); err != nil {
			log.Fatalf("failed to write server key to file %s: %v", keyFile.Name(), err)
		}
		log.Debugf("Storing server certificate to file %s", certFile.Name())
		log.Debugf("Storing server key to file %s", keyFile.Name())

		for _, listenIP := range httpSrvConfig.ListenIPs {
			srvAddr := net.JoinHostPort(
				listenIP, fmt.Sprintf("%d", httpSrvConfig.HTTPSPort))
			go func(addr string) {
				log.Debugf("HTTPS server listening on %s", addr)
				log.Fatalln(
					http.ListenAndServeTLS(addr, certFile.Name(), keyFile.Name(), nil))
			}(srvAddr)
		}
	}

	cancelChan := make(chan os.Signal, 1)
	// Catch termination or interrupt signal.
	signal.Notify(cancelChan, syscall.SIGTERM, syscall.SIGINT)
	sig := <-cancelChan
	log.Infof("Caught terimation/interrupt signal: %v, exiting...", sig)
}
