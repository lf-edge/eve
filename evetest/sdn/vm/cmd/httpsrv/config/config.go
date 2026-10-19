// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

// HTTPSrvConfig : HTTP server configuration formatted with JSON and passed to httpsrv
// using the "-c" command line argument.
type HTTPSrvConfig struct {
	// ListenIPs : IP addresses to listen on.
	// Leave empty to listen on all available interfaces instead of just
	// the interfaces with the given host address.
	ListenIPs []string `json:"listenIPs"`
	// LogFile : file to write all log messages into.
	LogFile string `json:"logFile"`
	// PidFile : file to write httpsrv process PID.
	PidFile string `json:"pidFile"`
	// Verbose : enable to have all requests logged.
	Verbose bool `json:"verbose"`
	// HTTPPort : port to listen for HTTP requests.
	// Zero value can be used to disable HTTP.
	HTTPPort uint16 `json:"httpPort"`
	// HTTPSPort : port to listen for HTTPS requests.
	// Zero value can be used to disable HTTPS.
	HTTPSPort uint16 `json:"httpsPort"`
	// CertPEM : Server certificate in the PEM format. Required for HTTPS.
	CertPEM string `json:"certPEM"`
	// KeyPEM : Server key in the PEM format. Required for HTTPS.
	KeyPEM string `json:"keyPEM"`
	// Maps URL Path to a content to be returned inside the HTTP(S) response body.
	Paths map[string]*api.HTTPContent `json:"paths"`
}
