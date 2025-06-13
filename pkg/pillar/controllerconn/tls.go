// Copyright (c) 2017-2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// tls.go contains helper functions for configuring and managing TLS settings in controllerconn.

package controllerconn

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"golang.org/x/crypto/ocsp"
)

// InitializeCertDir is called by zedbox to make sure we have the initial
// files in /persist/certs from /config/ under a sha-based name.
// Also, the currently used base file is indicated by the content of
// /persist/certs/v2tlsbaseroot-certificates.sha256. This is to prepare for a
// future feature where the controller can update the base file.
// Note that programmatically we add any proxy certificates to the list of roots
// we trust separately from the file content.
func InitializeCertDir(log *base.LogObject) error {
	if _, err := os.Stat(types.CertificateDirname); err != nil {
		log.Tracef("Create %s", types.CertificateDirname)
		if err := os.MkdirAll(types.CertificateDirname, 0700); err != nil {
			return err
		}
	}
	f, err := os.Open(types.V2TLSBaseFile)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		err = fmt.Errorf("Failed sha256 of %s: %w",
			types.V2TLSBaseFile, err)
		return err
	}
	sha := fmt.Sprintf("%x", h.Sum(nil))
	// Copy base file to /persist/certs/<sha> if not exist or zero length
	dstfile := fmt.Sprintf("%s/%s", types.CertificateDirname, sha)
	st, err := os.Stat(dstfile)
	if err != nil || st.Size() == 0 {
		log.Noticef("Adding /config/v2tlsbaseroot-certificates.pem to %s",
			dstfile)
		err := fileutils.CopyFile("/config/v2tlsbaseroot-certificates.pem", dstfile)
		if err != nil {
			return err
		}
	}
	// Write sha to types.V2TLSCertShaFilename if not exist or zero length
	dstfile = types.V2TLSCertShaFilename
	st, err = os.Stat(dstfile)
	if err != nil || st.Size() == 0 {
		log.Noticef("Setting /config/v2tlsbaseroot-certificates.pem as current")
		line := sha + "\n"
		err = fileutils.WriteRename(dstfile, []byte(line))
		if err != nil {
			return err
		}
	}
	return nil
}

// GetClientCert prepares tls.Certificate to connect to the Controller
func GetClientCert() (tls.Certificate, error) {
	if !etpm.IsTpmEnabled() {
		//Not a TPM capable device, return openssl certificate
		return tls.LoadX509KeyPair(types.DeviceCertName, types.DeviceKeyName)
	}

	// TPM capable device, return TPM bcased certificate
	deviceCertBytes, err := os.ReadFile(types.DeviceCertName)
	if err != nil {
		return tls.Certificate{}, err
	}
	deviceCertDERBytes, _ := pem.Decode(deviceCertBytes)
	deviceTLSCert := tls.Certificate{}
	deviceTLSCert.Certificate = append(deviceTLSCert.Certificate,
		deviceCertDERBytes.Bytes)

	tpmPrivKey := etpm.TpmPrivateKey{}
	tpmPrivKey.PublicKey = tpmPrivKey.Public()

	deviceTLSCert.PrivateKey = tpmPrivKey
	return deviceTLSCert, nil
}

// GetServerSigningCert returns the server (i.e. controller) signing certificate.
func (c *Client) GetServerSigningCert() *x509.Certificate {
	return c.serverSigningCert
}

// UpdateTLSConfig sets the TlsConfig based on current root CA certificates
// If a clientCert is specified it overrides the device*Name files.
func (c *Client) UpdateTLSConfig(clientCert *tls.Certificate) error {
	tlsConfig, err := c.GetTLSConfig(clientCert)
	if err != nil {
		return err
	}
	c.TLSConfig = tlsConfig
	return nil
}

// GetTLSConfig creates and returns a TLSConfig based on current root CA certificates
// If a clientCert is specified it overrides the device*Name files.
func (c *Client) GetTLSConfig(clientCert *tls.Certificate) (*tls.Config, error) {
	if clientCert == nil {
		deviceTLSCert, err := GetClientCert()
		if err != nil {
			return nil, err
		}
		clientCert = &deviceTLSCert
	}

	// Load CA certificates
	// The RootCA will have both wellknown signed CA and private root CA
	// This allows the V2 API transition to be decoupled from the server
	// certificate transition.
	// - First the server (controller) move to support V2
	// - Then edge devices move to new image with V2 support and start to use
	//   V2 API
	// - When all the remote edge devices are on V2 API capable image, the server
	//   can switch the certificate from private CA to well-known signed CA
	// Thus V1 device can only talk to server with private Root-CA, V2
	// device can talk to V2 enabled server with either private or well-known Root-CAs
	// and only V2 includes proxy Cert CA
	caCertPool := x509.NewCertPool()

	if c.v2API {
		// Load the well-known CAs
		line, err := os.ReadFile(types.V2TLSCertShaFilename)
		if err != nil {
			return nil, err
		}
		sha := strings.TrimSpace(string(line))
		if len(sha) == 0 {
			errStr := fmt.Sprintf("Read zero byte from sha file")
			c.log.Error(errStr)
			return nil, errors.New(errStr)
		}
		v2RootFilename := types.CertificateDirname + "/" + sha
		caCert, err := os.ReadFile(v2RootFilename)
		if err != nil {
			return nil, err
		}
		if !caCertPool.AppendCertsFromPEM(caCert) {
			errStr := fmt.Sprintf("Failed to append certs from %s",
				v2RootFilename)
			c.log.Error(errStr)
			return nil, errors.New(errStr)
		}

		// Append any proxy certs from any interface/port to caCertPool
		for _, port := range c.DeviceNetworkStatus.Ports {
			for _, pem := range port.ProxyConfig.ProxyCertPEM {
				if !caCertPool.AppendCertsFromPEM(pem) {
					pemStr := string(pem)
					// Keep the error message length reasonable.
					const maxPrintedLen = 128
					if len(pemStr) > maxPrintedLen {
						pemStr = pemStr[:maxPrintedLen/2] + "..." +
							pemStr[len(pemStr)-(maxPrintedLen/2):]
					}
					errStr := fmt.Sprintf("Failed to append ProxyCertPEM %s for %s",
						pemStr, port.IfName)
					c.log.Error(errStr)
					return nil, errors.New(errStr)
				}
			}
		}
	}

	// Also append the v1's private signed root-cert
	caCert1, err := os.ReadFile(types.RootCertFileName)
	if err != nil {
		return nil, err
	}
	caCertStr := string(caCert1) // prevent potential memory leak
	if !caCertPool.AppendCertsFromPEM([]byte(caCertStr)) {
		errStr := fmt.Sprintf("Failed to append certs from %s",
			types.RootCertFileName)
		c.log.Error(errStr)
		return nil, errors.New(errStr)
	}

	// Add on proxy certs if any
	if c.v2API {
		// save the proxy certs in the Client's internal variable, could be empty
		c.prevCertPEM = c.cacheProxyCerts()
	}

	// Note that we do not set ServerName here (used to verify the hostname on the returned
	// certificates and as the SNI value of the ClientHello TLS message).
	// Instead, we let the higher-level packages like net/http [1] and gorilla/websocket [2]
	// to set it automatically from the destination URL.
	// Setting this manually actually breaks certificate verification when (non-transparent)
	// network proxy listening on HTTPS is being used between the device and the destination.
	// In that case, the first TLS handshake is being done with the proxy and it is expected
	// that proxy presents its own certificate, with CN set to its hostname.
	// With ServerName set to destination hostname already for this first TLS handshake,
	// proxy cert verification would fail with:
	//   proxyconnect tcp: x509: certificate is valid for <proxy-hostname>, not <destination-hostname>
	// Higher-level packages first set ServerName to the proxy hostname, then for the subsequent
	// TLS handshake they use the destination hostname.
	//
	// [1]: https://github.com/golang/go/blob/release-branch.go1.16/src/net/http/transport.go#L1511-L1513
	// [2]: https://github.com/gorilla/websocket/blob/v1.5.0/client.go#L340-L342
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*clientCert},
		RootCAs:      caCertPool,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		// TLS 1.2 because we can
		MinVersion: tls.VersionTLS12,
		// Session Resumption, zero means using the default, which is 64
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
	}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig, nil
}

func (c *Client) cacheProxyCerts() [][]byte {
	var certPEM [][]byte
	// find all unique certs and save them
	for _, port := range c.DeviceNetworkStatus.Ports {
		for _, pem := range port.ProxyCertPEM {
			if !c.containsCert(certPEM, pem) {
				certPEM = append(certPEM, pem)
			}
		}
	}
	return certPEM
}

func (c *Client) containsCert(certPEM [][]byte, pem []byte) bool {
	for _, prevPEM := range certPEM {
		if bytes.Equal(prevPEM, pem) {
			return true
		}
	}
	return false
}

// Returns true if the set of proxy certificates changed.
func (c *Client) checkProxyCertsChanged() bool {
	newCerts := c.cacheProxyCerts()
	if len(newCerts) != len(c.prevCertPEM) {
		return true
	}

	for _, pem := range newCerts {
		foundIt := false
		for _, pem2 := range c.prevCertPEM {
			if bytes.Equal(pem, pem2) {
				foundIt = true
				break
			}
		}
		if !foundIt {
			return true // new one not in prev
		}
	}

	return false // both has same pems or both empty, no change
}

// UpdateTLSProxyCerts - Update when DeviceNetworkStatus changes
func (c *Client) UpdateTLSProxyCerts() bool {
	if c.TLSConfig == nil || c.DeviceNetworkStatus == nil {
		c.log.Errorln("UpdateTLSProxyCerts: tlsconfig or DeviceNetworkStatus missing")
		return false
	}

	if !c.checkProxyCertsChanged() {
		// we have the proxy certs already or both empty, no change
		return false
	}

	var caCertPool *x509.CertPool
	if len(c.prevCertPEM) > 0 {

		// previous certs we have are different, lets rebuild from beginning
		caCertPool = x509.NewCertPool()
		line, err := os.ReadFile(types.V2TLSCertShaFilename)
		if err != nil {
			errStr := fmt.Sprintf("Failed to read V2TLSCertShaFilename")
			c.log.Error(errStr)
			return false
		}
		sha := strings.TrimSpace(string(line))
		if len(sha) == 0 {
			errStr := fmt.Sprintf("Read zero byte from sha file")
			c.log.Error(errStr)
			return false
		}
		v2RootFilename := types.CertificateDirname + "/" + sha
		caCert, err := os.ReadFile(v2RootFilename)
		if err != nil {
			errStr := fmt.Sprintf("Failed to read v2RootFilename")
			c.log.Error(errStr)
			return false
		}
		if !caCertPool.AppendCertsFromPEM(caCert) {
			errStr := fmt.Sprintf("Failed to append certs from %s", v2RootFilename)
			c.log.Error(errStr)
			return false
		}
		c.log.Functionf("UpdateTLSProxyCerts: rebuild root CA\n")
	} else {
		// we don't have proxy certs, add them if any exist
		caCertPool = c.TLSConfig.RootCAs
	}

	if caCertPool == nil {
		errStr := fmt.Sprintf("caCertPool is nil")
		c.log.Error(errStr)
		return false
	}

	// AppendCertsFromPEM checks duplicates inside
	for _, port := range c.DeviceNetworkStatus.Ports {
		for _, pem := range port.ProxyCertPEM {
			if !caCertPool.AppendCertsFromPEM(pem) {
				errStr := fmt.Sprintf("Failed to append certs from proxy pem")
				c.log.Error(errStr)
				return false
			}
		}
	}

	// May updating the /etc/ssl/certs for proxy certs in /usr/local/share/ca-certificates directory
	c.updateEtcSSLforProxyCerts()

	c.log.Functionf("UpdateTLSProxyCerts: root CA updated")
	c.TLSConfig.RootCAs = caCertPool
	// save the new proxy Certs, or null it out
	c.prevCertPEM = c.cacheProxyCerts()
	return true
}

func (c *Client) stapledCheck(connState *tls.ConnectionState) (bool, error) {
	if connState.OCSPResponse == nil {
		return false, errors.New("no OCSP response")
	}
	if connState.VerifiedChains == nil {
		return false, errors.New("stapledCheck: No VerifiedChains")

	}
	if len(connState.VerifiedChains[0]) == 0 {
		return false, errors.New("stapledCheck: No VerifiedChains 2")

	}

	issuer := connState.VerifiedChains[0][1]
	resp, err := ocsp.ParseResponse(connState.OCSPResponse, issuer)
	if err != nil {
		return false,
			fmt.Errorf("stapledCheck: error parsing response: %s ",
				err)

	}
	now := time.Now()
	age := now.Unix() - resp.ProducedAt.Unix()
	remain := resp.NextUpdate.Unix() - now.Unix()
	c.log.Tracef("OCSP age %d, remain %d\n", age, remain)
	if remain < 0 {
		return false, errors.New("OCSP expired.")
	}
	switch resp.Status {
	case ocsp.Good:
		c.log.Traceln("Certificate Status Good.")
		return true, nil
	case ocsp.Unknown:
		return false, errors.New("Certificate Status Unknown")
	case ocsp.Revoked:
		return false, errors.New("Certificate Status Revoked")
	default:
		return false, fmt.Errorf("Unknown OCSP status %d", resp.Status)
	}
}

func (c *Client) updateEtcSSLforProxyCerts() {
	// Only zedagent is to update the host ca-certificates
	if !c.v2API || c.AgentName != "zedagent" {
		c.log.Functionf("updateEtcSSLforProxyCerts: skip agent %s", c.AgentName)
		return
	}

	proxyCertPrefix := "/proxy-cert-"
	proxyCertDirFile := types.ShareCertDirname + proxyCertPrefix
	err := filepath.Walk(types.ShareCertDirname,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				c.log.Error(err)
			}
			if path != types.ShareCertDirname && info.IsDir() {
				return filepath.SkipDir
			}
			if strings.HasPrefix(path, proxyCertDirFile) {
				c.log.Functionf("updateEtcSSLforProxyCerts: remove file %s", path)
				os.Remove(path)
			}
			return err
		})
	if err != nil {
		c.log.Errorf("updateEtcSSLforProxyCerts: reomove proxy certs (%s)", err)
	}

	newCerts := c.cacheProxyCerts()
	for i, pem := range newCerts {
		proxyFilename := proxyCertDirFile + strconv.Itoa(i) + ".pem"
		err = fileutils.WriteRename(proxyFilename, pem)
		if err != nil {
			c.log.Errorf("updateEtcSSLforProxyCerts: file %s save err %v",
				proxyFilename, err)
		}
		c.log.Functionf("updateEtcSSLforProxyCerts: file saved to %s", proxyFilename)
	}

	cmdName := "/usr/sbin/update-ca-certificates"
	c.log.Functionf("updateEtcSSLforProxyCerts: Calling command %s", cmdName)
	out, err := base.Exec(c.log, cmdName).CombinedOutput()
	if err != nil {
		c.log.Errorf("updateEtcSSLforProxyCerts: update-ca-certificates, certs num %d, (%s)",
			len(newCerts), err)
	} else {
		c.log.Functionf("updateEtcSSLforProxyCerts: update-ca-certificates %s, certs num %d",
			out, len(newCerts))
	}
}
