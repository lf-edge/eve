// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Create a non-CA certificate with arbitrarily short lifetime and ECDSA keys.
// Signed by a CA cert.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

const lifetimeInSecs = 1200

var (
	caCert         *x509.Certificate
	caPrivKey      *ecdsa.PrivateKey
	caCertName     = "ca.cert.pem"
	caKeyName      = "ca.key.pem"
	outputDir      = "."
	certCommonName = ""
	certOrg        = ""
)

func main() {
	var (
		keyName  string
		certName string
		notAfter time.Time
	)

	outputPrefixPtr := flag.String("o", "signing", "prefix for output files")
	lifetimePtr := flag.Int("l", lifetimeInSecs, "cert lifetime in seconds")
	isCAPtr := flag.Bool("C", false, "generate CA cert")
	caCertPathPtr := flag.String("ca-cert", caCertName, "CA certificate file")
	caKeyPathPtr := flag.String("ca-key", caKeyName, "CA key file")
	outputDirPtr := flag.String("output-dir", "", "Output directory for cert and key files")
	certCnPtr := flag.String("cert-cn", "", "Common Name for the certificate")
	certOPtr := flag.String("cert-o", "", "Organization for the certificate")
	flag.Parse()

	if *outputDirPtr != "" {
		outputDir = *outputDirPtr
	}
	if *certCnPtr != "" {
		certCommonName = *certCnPtr
	}
	if *certOPtr != "" {
		certOrg = *certOPtr
	}

	if *isCAPtr {
		notAfter = time.Now().AddDate(20, 0, 0)
		// Fixed names
		certName = caCertName
		keyName = caKeyName
	} else {
		// Read CA from ca.cert.name and ca.key.name
		var err error
		caCert, err = GetCertFromFile(*caCertPathPtr)
		if err != nil {
			fmt.Printf("GetCertFromFile failed: %s\n", err)
			return
		}
		caPrivKey, err = GetPrivateKeyFromFile(*caKeyPathPtr)
		if err != nil {
			fmt.Printf("GetPrivateKeyFromFile failed: %s\n", err)
			return
		}
		notAfter = time.Now().Add(time.Second * time.Duration(*lifetimePtr))
		timeStamp := notAfter.Format("2006-01-02T150405Z0700")
		fmt.Printf("End: %s\n", timeStamp)
		outputPrefix := *outputPrefixPtr + "." + timeStamp
		certName = outputPrefix + ".cert.pem"
		keyName = outputPrefix + ".key.pem"
	}
	if err := createCert(*isCAPtr, notAfter, certName, keyName); err != nil {
		fmt.Printf("failed: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Wrote %s and %s\n", certName, keyName)
}

// generate a key and certificate,
// the certificate is self-signed using the private key unless isCA
// Assumes no TPM hence device private key is in a file
func createCert(isCA bool, notAfter time.Time, certName string, keyName string) error {
	// Generate private key
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("Failed to generate software device key pair: %v",
			err)
	}

	// get the device cert template
	template := createCertTemplate(isCA, notAfter)
	// Who will sign? Self-signed if CA
	var ca = caCert
	if isCA {
		ca = template
		caPrivKey = certPrivKey
	}

	derBytes, err := x509.CreateCertificate(rand.Reader,
		template, ca, certPrivKey.Public(), caPrivKey)
	if err != nil {
		return fmt.Errorf("Failed to create device certificate: %w",
			err)
	}

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	// public cert bytes
	certBytes := pem.EncodeToMemory(certBlock)
	if certBytes == nil {
		return fmt.Errorf("Failed in PEM encoding of device cert: empty bytes")
	}

	// private cert bytes
	privBytes, err := x509.MarshalPKCS8PrivateKey(certPrivKey)
	if err != nil {
		return fmt.Errorf("Failed in MarshalECPrivateKey of ECDH cert: %v", err)
	}
	keyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}

	keyBytes := pem.EncodeToMemory(keyBlock)
	if keyBytes == nil {
		return fmt.Errorf("Failed in PEM encoding of ECDH key: empty bytes")
	}
	return writeDeviceCertToFile(certName, certBytes, keyName, keyBytes)
}

func writeDeviceCertToFile(certName string, certBytes []byte, keyName string, keyBytes []byte) error {
	if err := os.WriteFile(outputDir+"/"+keyName, keyBytes, 0600); err != nil {
		return err
	}
	return os.WriteFile(outputDir+"/"+certName, certBytes, 0644)
}

// create deviceCert Template with requested lifetime
func createCertTemplate(isCA bool, notAfter time.Time) *x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	// Backdate one day in case clock is off a bit
	// XXX adjust this?
	yesterday := time.Now().AddDate(0, 0, -1)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{certOrg},
			CommonName:   certCommonName,
		},
		NotBefore: yesterday,
		NotAfter:  notAfter,
		IsCA:      isCA,
		// No x509.KeyUsageKeyEncipherment for ECC
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	return &template
}

// GetPrivateKeyFromFile reads a private key file
func GetPrivateKeyFromFile(keyFile string) (*ecdsa.PrivateKey, error) {
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	//Following logic is derived from steps in
	//https://golang.org/src/crypto/tls/tls.go:X509KeyPair()
	var keyDERBlock *pem.Block
	var skippedBlockTypes []string
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return nil, errors.New("Failed to find any PEM data in key input")
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return nil, errors.New("Got a certificate instead of key")
			}
			return nil, errors.New("No PEM block found with type PRIVATE KEY")
		}
		if keyDERBlock.Type == "PRIVATE KEY" ||
			strings.HasSuffix(keyDERBlock.Type, "EC PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}
	if key, err := x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes); err == nil {
		var pkey *ecdsa.PrivateKey
		var ok bool
		if pkey, ok = key.(*ecdsa.PrivateKey); !ok {
			return nil, errors.New("Private key is not ecdsa type")
		}
		return pkey, nil
	}
	if key, err := x509.ParseECPrivateKey(keyDERBlock.Bytes); err == nil {
		return key, nil
	} else {
		return nil, err
	}
}

// GetCertFromFile reads a X.509 cert
func GetCertFromFile(certFile string) (*x509.Certificate, error) {
	//read public key from ecdh certificate
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		fmt.Printf("error in reading ecdh cert file: %v", err)
		return nil, err
	}
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("error in parsing ecdh cert file: %v", err)
		return nil, err
	}
	return cert, nil
}
