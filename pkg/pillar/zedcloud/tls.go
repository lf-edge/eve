// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Common code to communicate to zedcloud

package zedcloud

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/cmd/tpmmgr"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
	"io"
	"io/ioutil"
	"math/big"
	"strings"
	"time"
)

//TpmPrivateKey is Custom implementation of crypto.PrivateKey interface
type TpmPrivateKey struct {
	PublicKey crypto.PublicKey
}

//Helper structure to pack ecdsa signature for ASN1 encoding
type ecdsaSignature struct {
	R, S *big.Int
}

//Public implements crypto.PrivateKey interface
func (s TpmPrivateKey) Public() crypto.PublicKey {
	clientCertBytes, err := ioutil.ReadFile(types.DeviceCertName)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(clientCertBytes)
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	ecdsaPublicKey := cert.PublicKey.(*ecdsa.PublicKey)
	return ecdsaPublicKey
}

//Sign implements cryto.PrivateKey interface
func (s TpmPrivateKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	R, S, err := tpmmgr.TpmSign(digest)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ecdsaSignature{R, S})
}

//GetClientCert prepares tls.Certificate to connect to the cloud Controller
func GetClientCert() (tls.Certificate, error) {
	if !tpmmgr.IsTpmEnabled() {
		//Not a TPM capable device, return openssl certificate
		return tls.LoadX509KeyPair(types.DeviceCertName, types.DeviceKeyName)
	}

	// TPM capable device, return TPM bcased certificate
	deviceCertBytes, err := ioutil.ReadFile(types.DeviceCertName)
	if err != nil {
		return tls.Certificate{}, err
	}
	deviceCertDERBytes, _ := pem.Decode(deviceCertBytes)
	deviceTLSCert := tls.Certificate{}
	deviceTLSCert.Certificate = append(deviceTLSCert.Certificate,
		deviceCertDERBytes.Bytes)

	tpmPrivKey := TpmPrivateKey{}
	tpmPrivKey.PublicKey = tpmPrivKey.Public()

	deviceTLSCert.PrivateKey = tpmPrivKey
	return deviceTLSCert, nil
}

// UpdateTLSConfig sets the TlsConfig based on current root CA certificates
// If a server arg is specified it overrides the serverFilename content.
// If a clientCert is specified it overrides the device*Name files.
func UpdateTLSConfig(zedcloudCtx *ZedCloudContext, serverName string, clientCert *tls.Certificate) error {
	tlsConfig, err := GetTlsConfig(zedcloudCtx.DeviceNetworkStatus, serverName, clientCert,
		zedcloudCtx.V2API)
	if err != nil {
		return err
	}
	zedcloudCtx.TlsConfig = tlsConfig
	return nil
}

// GetTlsConfig creates and returns a TlsConfig based on current root CA certificates
// If a server arg is specified it overrides the serverFilename content.
// If a clientCert is specified it overrides the device*Name files.
func GetTlsConfig(dns *types.DeviceNetworkStatus, serverName string, clientCert *tls.Certificate, v2api bool) (*tls.Config, error) {
	if serverName == "" {
		// get the server name
		bytes, err := ioutil.ReadFile(types.ServerFileName)
		if err != nil {
			return nil, err
		}
		strTrim := strings.TrimSpace(string(bytes))
		serverName = strings.Split(strTrim, ":")[0]
	}
	if clientCert == nil {
		deviceTLSCert, err := GetClientCert()
		if err != nil {
			return nil, err
		}
		clientCert = &deviceTLSCert
	}

	// Load CA certificates
	caCertPool := x509.NewCertPool()
	if v2api {
		line, err := ioutil.ReadFile(types.V2TLSCertShaFilename)
		if err != nil {
			return nil, err
		}
		sha := strings.TrimSpace(string(line))
		v2RootFilename := types.CertificateDirname + "/" + sha
		caCert, err := ioutil.ReadFile(v2RootFilename)
		if err != nil {
			return nil, err
		}
		if !caCertPool.AppendCertsFromPEM(caCert) {
			errStr := fmt.Sprintf("Failed to append certs from %s",
				v2RootFilename)
			log.Errorf(errStr)
			return nil, errors.New(errStr)
		}
		// Append any proxy certs from any interface/port to caCertPool
		for _, port := range dns.Ports {
			for _, pem := range port.ProxyConfig.ProxyCertPEM {
				log.Infof("XXX adding proxycerts from %s", port.IfName)
				if !caCertPool.AppendCertsFromPEM(pem) {
					errStr := fmt.Sprintf("Failed to append ProxyCertPEM %s for %s",
						string(pem), port.IfName)
					log.Errorf(errStr)
					return nil, errors.New(errStr)
				}
			}
		}
	} else {
		caCert, err := ioutil.ReadFile(types.RootCertFileName)
		if err != nil {
			return nil, err
		}
		if !caCertPool.AppendCertsFromPEM(caCert) {
			errStr := fmt.Sprintf("Failed to append certs from %s",
				types.RootCertFileName)
			log.Errorf(errStr)
			return nil, errors.New(errStr)
		}
	}
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
	if connState.VerifiedChains == nil {
		log.Errorln("stapledCheck: No VerifiedChains")
		return false
	}
	if len(connState.VerifiedChains[0]) == 0 {
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
