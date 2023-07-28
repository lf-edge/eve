// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//unit-tests for tpmmgr

package tpmmgr

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
)

const ecdhCertPem = `
-----BEGIN CERTIFICATE-----
MIICBzCCAa2gAwIBAgIRAKTAKfe3M1c0LVjjkgd5QeYwCgYIKoZIzj0EAwIwYDEL
MAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFDASBgNVBAcMC1NhbnRh
IENsYXJhMRQwEgYDVQQKDAtaZWRlZGEsIEluYzEQMA4GA1UEAwwHb25ib2FyZDAe
Fw0yMDA3MTMxMTU5NTdaFw00MDA3MDgxMTU5NTdaMHMxCzAJBgNVBAYTAlVTMQsw
CQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEdMBsGA1UEChMUVGhl
IExpbnV4IEZvdW5kYXRpb24xIDAeBgNVBAMTF0RldmljZSBFQ0RIIGNlcnRpZmlj
YXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnFLYeXVZ+SJniG0+QoqYRKDy
EXx6Cs7+DyY+RcKQG16NsrkTCMXU4e4B2gmrtXXT02i8ewLeUQVXpkq00m6oqKM1
MDMwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwCgYIKoZIzj0EAwIDSAAwRQIhAIwMDRIHRNxEliWSM8QcoHxt5o1Wk7v+
I76qEHIg0L9NAiBiPY2Llo/bNdn6Q7MJBY7Cqlq+pFhqXr1gjzULQDoP5w==
-----END CERTIFICATE-----
`

const ecdhKeyPem = `
-----BEGIN PRIVATE KEY-----
MHcCAQEEIDK0dBttLvxNuoDfWnb/rkL2PCQw5zkx7GAUxKNNii4koAoGCCqGSM49
AwEHoUQDQgAEnFLYeXVZ+SJniG0+QoqYRKDyEXx6Cs7+DyY+RcKQG16NsrkTCMXU
4e4B2gmrtXXT02i8ewLeUQVXpkq00m6oqA==
-----END PRIVATE KEY-----
`

const ecdhKeyPemLegacy = `
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMxnOmOgQvSj8WunVA9jh35PxI//5J4SwOejh+gkDIG2oAoGCCqGSM49
AwEHoUQDQgAE2XOAHcLF+qfQf6vdd1KsGky6XlQQ62Srl9siwcTHvK1FChMJPpLD
ZH/v/30uqPXQKtnUZLe+g/FThQ9Y3uDimw==
-----END EC PRIVATE KEY-----
`

const attestCertPem = `
-----BEGIN CERTIFICATE-----
MIICDjCCAbOgAwIBAgIQYl4iR/oRi883qpeVSuD81zAKBggqhkjOPQQDAjBgMQsw
CQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEUMBIGA1UEBwwLU2FudGEg
Q2xhcmExFDASBgNVBAoMC1plZGVkYSwgSW5jMRAwDgYDVQQDDAdvbmJvYXJkMB4X
DTIwMDcxMzExNTk1N1oXDTQwMDcwODExNTk1N1owejELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMR0wGwYDVQQKExRUaGUg
TGludXggRm91bmRhdGlvbjEnMCUGA1UEAxMeRGV2aWNlIEF0dGVzdGF0aW9uIGNl
cnRpZmljYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2C3PaeZV5clxI8Go
LdP9AYIrMogd6owH4hexe7zt2kCvpYsltcSSreLp2TWZoqp6IKY1ldgxy/Y3PdA7
4w8RqKM1MDMwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwG
A1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSQAwRgIhAK5BosnQVb0/+2FMfVT/FtZJ
8Brrf6kKfMWKxA61rIFsAiEAznEDZEqUxZ8Y1U81u9/p5ND5Tv7b8bmxE9fS67OY
ZaU=
-----END CERTIFICATE-----
`

const attestKeyPem = `
-----BEGIN PRIVATE KEY-----
MHcCAQEEINB4uzv6pRFZmRkNiWb6XGgEBaEmA0dXkV1vq7Rb/FFCoAoGCCqGSM49
AwEHoUQDQgAE2C3PaeZV5clxI8GoLdP9AYIrMogd6owH4hexe7zt2kCvpYsltcSS
reLp2TWZoqp6IKY1ldgxy/Y3PdA74w8RqA==
-----END PRIVATE KEY-----
`

const deviceKeyPem = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHfsn9qpN+BpoP3kjjpkiwmKe2ANC8t9Bs3rW0Hog0WsoAoGCCqGSM49
AwEHoUQDQgAExA9zs0+fsiYWzG1418iSdxUjqgWuzfY1nwHswtAtZSRWq4sQFWj4
PQLKLsvKHxLevrLaPG6DEYYYWa/0ITpyGg==
-----END EC PRIVATE KEY-----
`

const deviceCertPem = `
-----BEGIN CERTIFICATE-----
MIIBkzCCAToCCQDZAWM5AYD0pzAKBggqhkjOPQQDAjBEMRMwEQYDVQQKDApaZWRl
ZGEgSW5jMS0wKwYDVQQDDCQ1ZDA3NjdlZS0wNTQ3LTQ1NjktYjUzMC0zODdlNTI2
ZjhjYjkwHhcNMjAwNzEzMTE1OTU3WhcNNDAwNzA4MTE1OTU3WjBgMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEUMBIGA1UEBwwLU2FudGEgQ2xhcmEx
FDASBgNVBAoMC1plZGVkYSwgSW5jMRAwDgYDVQQDDAdvbmJvYXJkMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAExA9zs0+fsiYWzG1418iSdxUjqgWuzfY1nwHswtAt
ZSRWq4sQFWj4PQLKLsvKHxLevrLaPG6DEYYYWa/0ITpyGjAKBggqhkjOPQQDAgNH
ADBEAiAVnvsXKf1FbqoF5HvAu1KAdat+Oh/Np2ArLXsxUz9xpgIgLBo/rSuV9nTf
xYIAQpVm4p2mQ3IE8hf6Tw1Q5iDajik=
-----END CERTIFICATE-----
`
const (
	testEcdhCertFile      = "test_ecdh.cert.pem"
	testEcdhKeyFile       = "test_ecdh.key.pem"
	testEcdhKeyLegacyFile = "test_ecdh_legacy_key.pem"
	testDeviceKeyFile     = "test_device.key.pem"
)

// Test ECDH key exchange and a symmetric cipher based on ECDH, with software based keys
func TestSoftEcdh(t *testing.T) {
	//Redirect ECDH cert/key files to test files
	ecdhCertFile = testEcdhCertFile
	ecdhKeyFile := testEcdhKeyFile
	etpm.SetECDHPrivateKeyFile(ecdhKeyFile)

	err := os.WriteFile(ecdhCertFile, []byte(ecdhCertPem), 0644)
	if err != nil {
		t.Errorf("Failed to create test certificate file: %v", err)
	}
	defer os.Remove(ecdhCertFile)

	err = os.WriteFile(ecdhKeyFile, []byte(ecdhKeyPem), 0644)
	if err != nil {
		t.Errorf("Failed to create test key file: %v", err)
	}
	defer os.Remove(ecdhKeyFile)

	if err = testEcdhAES(); err != nil {
		t.Errorf("%v", err)
	}
}

// Test ECDH key exchange and a symmetric cipher based on ECDH, with software based keys
func TestGetPrivateKeyFromFile(t *testing.T) {
	err := os.WriteFile(testEcdhKeyFile, []byte(ecdhKeyPem), 0644)
	if err != nil {
		t.Errorf("Failed to create test ecdh key file: %v", err)
	}
	defer os.Remove(testEcdhKeyFile)

	err = os.WriteFile(testDeviceKeyFile, []byte(deviceKeyPem), 0644)
	if err != nil {
		t.Errorf("Failed to create test device key file: %v", err)
	}
	defer os.Remove(testDeviceKeyFile)

	err = os.WriteFile(testEcdhKeyLegacyFile, []byte(ecdhKeyPemLegacy), 0644)
	if err != nil {
		t.Errorf("Failed to create test ecdh legacy key file: %v", err)
	}
	defer os.Remove(testEcdhKeyLegacyFile)

	if _, err = etpm.GetPrivateKeyFromFile(testEcdhKeyFile); err != nil {
		t.Errorf("%v", err)
	}

	if _, err = etpm.GetPrivateKeyFromFile(testDeviceKeyFile); err != nil {
		t.Errorf("%v", err)
	}

	if _, err = etpm.GetPrivateKeyFromFile(testEcdhKeyLegacyFile); err != nil {
		t.Errorf("%v", err)
	}
}

func verifyCert(leafCert, rootCert string) error {
	block, _ := pem.Decode([]byte(leafCert))
	if block == nil {
		return fmt.Errorf("unable to decode server certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("unable to parse certificate: %s", err)
	}

	//Create the set of root certificates...
	roots := x509.NewCertPool()

	if ok := roots.AppendCertsFromPEM([]byte(rootCert)); !ok {
		return fmt.Errorf("failed to parse root certificate")
	}

	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
	}
	_, err = cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("failed to verify certificate chain: %s", err)
	}
	return nil
}

func TestVerifyEdgeNodeCerts(t *testing.T) {
	if err := verifyCert(ecdhCertPem, deviceCertPem); err != nil {
		t.Errorf("ECDH cert verification failed with err: %v", err)
		return
	}
	if err := verifyCert(attestCertPem, deviceCertPem); err != nil {
		t.Errorf("Attestation cert verification failed with err: %v", err)
		return
	}
}

func TestSealUnseal(t *testing.T) {
	_, err := os.Stat(etpm.TpmDevicePath)
	if err != nil {
		t.Skip("TPM is not available, skipping the test.")
	}

	dataToSeal := []byte("secret")
	if err := etpm.SealDiskKey(dataToSeal, etpm.DiskKeySealingPCRs); err != nil {
		t.Errorf("Seal operation failed with err: %v", err)
		return
	}
	unsealedData, err := etpm.UnsealDiskKey(etpm.DiskKeySealingPCRs)
	if err != nil {
		t.Errorf("Unseal operation failed with err: %v", err)
		return
	}
	if !reflect.DeepEqual(dataToSeal, unsealedData) {
		t.Errorf("Seal/Unseal operation failed, want %v, but got %v", dataToSeal, unsealedData)
	}
}

func TestSealUnsealMismatchReport(t *testing.T) {
	_, err := os.Stat(etpm.TpmDevicePath)
	if err != nil {
		t.Skip("TPM is not available, skipping the test.")
	}

	rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
	if err != nil {
		t.Errorf("OpenTPM failed with err: %v", err)
		return
	}
	defer rw.Close()

	dataToSeal := []byte("secret")
	if err := etpm.SealDiskKey(dataToSeal, etpm.DiskKeySealingPCRs); err != nil {
		t.Errorf("Seal operation failed with err: %v", err)
		return
	}

	pcrIndexes := [3]int{1, 7, 8}
	pcrValue := bytes.Repeat([]byte{0xF}, sha256.Size)
	for _, pcr := range pcrIndexes {
		if err = tpm2.PCRExtend(rw, tpmutil.Handle(pcr), tpm2.AlgSHA256, pcrValue, ""); err != nil {
			t.Errorf("Failed to extend PCR %d: %s", pcr, err)
			return
		}
	}

	_, err = etpm.UnsealDiskKey(etpm.DiskKeySealingPCRs)
	if err == nil {
		t.Errorf("Expected error from UnsealDiskKey, got nil")
		return
	}

	if !strings.Contains(err.Error(), "[1 7 8]") {
		t.Errorf("UnsealDiskKey expected to report mismatching PCR indexes, got : %v", err)
		return
	}
}

func TestExtendAppPcrWithDeviceIdentity(t *testing.T) {
	_, err := os.Stat(etpm.TpmDevicePath)
	if err != nil {
		t.Skip("TPM is not available, skipping the test.")
	}

	logger, log = agentlog.InitNoRedirect("tpmmgr")
	file, err := ioutil.TempFile("/tmp", "tpmcred")
	if err != nil {
		t.Error(err)
		return
	}
	defer os.Remove(file.Name())
	credFile := file.Name()

	rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
	if err != nil {
		t.Errorf("failed to open TPM device handle: %v", err)
		return
	}
	defer rw.Close()

	// undefine the NV so we get a fresh cred for device
	err = tpm2.NVUndefineSpace(rw, etpm.EmptyPassword, tpm2.HandleOwner, etpm.TpmPasswdHdl)
	if err != nil {
		t.Errorf("NVUndefineSpace failed: %v", err)
		return
	}

	if err = genCredentials(credFile); err != nil {
		t.Errorf("failed to generate credentials: %v", err)
		return
	}

	pcrExtend := func(old, new []byte) []byte {
		h := sha256.New()
		h.Write(old)
		h.Write(new)
		return h.Sum(nil)
	}

	// Read cred and calc sha256(0 || cred)
	tpmCredentialBytes, err := os.ReadFile(credFile)
	if err != nil {
		t.Errorf("failed to read credentials: %v", err)
		return
	}

	s := sha256.Sum256(tpmCredentialBytes)
	expected := pcrExtend(bytes.Repeat([]byte{0x00}, sha256.Size), s[:])

	// Get the PCR value from TPM
	if err = extendAppPcrWithCredentials(credFile); err != nil {
		t.Errorf("extendAppPcrWithCredentials failed: %v", err)
		return
	}

	pcrVal, err := tpm2.ReadPCR(rw, int(applicationPCR), tpm2.AlgSHA256)
	if err != nil {
		t.Errorf("failed reading PCR-%d: %v", applicationPCR, err)
		return
	}

	// compare
	t.Logf("expected PCR[%d] : %x\n", applicationPCR, expected)
	t.Logf("returned PCR[%d] : %x\n", applicationPCR, pcrVal)

	if !bytes.Equal(expected, pcrVal) {
		t.Errorf("expected PCR value doesn't match the returned value: %v", err)
	}
}
