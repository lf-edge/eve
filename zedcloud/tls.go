// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// Common code to communicate to zedcloud

package zedcloud

import (
	"crypto/tls"
	"crypto/x509"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"strings"
	"time"
)

const (
	identityDirname = "/config"
	serverFilename  = identityDirname + "/server"
	deviceCertName  = identityDirname + "/device.cert.pem"
	deviceKeyName   = identityDirname + "/device.key.pem"
	rootCertName    = identityDirname + "/root-certificate.pem"
)

// If a server arg is specified it overrides the serverFilename content.
// If a clientCert is specified it overrides the device*Name files.
func GetTlsConfig(serverName string, clientCert *tls.Certificate) (*tls.Config, error) {
	if serverName == "" {
		// get the server name
		bytes, err := ioutil.ReadFile(serverFilename)
		if err != nil {
			return nil, err
		}
		strTrim := strings.TrimSpace(string(bytes))
		serverName = strings.Split(strTrim, ":")[0]
	}
	if clientCert == nil {
		deviceCert, err := tls.LoadX509KeyPair(deviceCertName,
			deviceKeyName)
		if err != nil {
			return nil, err
		}
		clientCert = &deviceCert
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(rootCertName)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*clientCert},
		ServerName:   serverName,
		RootCAs:      caCertPool,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		// TLS 1.2 because we can
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig, nil
}

func stapledCheck(connState *tls.ConnectionState) bool {
	if connstate.VerifiedChains == nil {
		log.Errorln("stapledCheck: No VerifiedChains")
		return false
	}
	if len(connstate.VerifiedChains[0]) == 0 {
		log.Errorln("stapledCheck: No VerifiedChains 2")
		return false
	}

	issuer := connState.VerifiedChains[0][1]
	resp, err := ocsp.ParseResponse(connState.OCSPResponse, issuer)
	if err != nil {
		log.Errorln("stapledCheck: error parsing response: ", err)
		return false
	}
	now := time.Now()
	age := now.Unix() - resp.ProducedAt.Unix()
	remain := resp.NextUpdate.Unix() - now.Unix()
	log.Debugf("OCSP age %d, remain %d\n", age, remain)
	if remain < 0 {
		log.Errorln("OCSP expired.")
		return false
	}
	if resp.Status == ocsp.Good {
		log.Debugln("Certificate Status Good.")
	} else if resp.Status == ocsp.Unknown {
		log.Errorln("Certificate Status Unknown")
	} else {
		log.Errorln("Certificate Status Revoked")
	}
	return resp.Status == ocsp.Good
}
