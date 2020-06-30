// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//unit-tests for tpmmgr

package tpmmgr

import (
	"io/ioutil"
	"os"
	"testing"
)

const ecdhCertPem = `
-----BEGIN CERTIFICATE-----
MIIB+zCCAaKgAwIBAgIRAKKyNDaW6z/niYCPGHUdQYIwCgYIKoZIzj0EAwIwYDEL
MAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFDASBgNVBAcMC1NhbnRh
IENsYXJhMRQwEgYDVQQKDAtaZWRlZGEsIEluYzEQMA4GA1UEAwwHb25ib2FyZDAe
Fw0yMDAyMTkwMjMzNThaFw00MDAyMTQwMjMzNThaMGgxCzAJBgNVBAYTAlVTMQsw
CQYDVQQIEwJDQTEUMBIGA1UEBxMLU2FudGEgQ2xhcmExFDASBgNVBAoTC1plZGVk
YSwgSW5jMSAwHgYDVQQDExdEZXZpY2UgRUNESCBjZXJ0aWZpY2F0ZTBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABOtXcZvEPvJkTPrt8H7w4A1r8tFpUEoSabH1V+9p
DWTsZiBGC+pZ2B0dff3wrQCA02MrqX/dlzQQrkZrTxXK6aejNTAzMA4GA1UdDwEB
/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMAoGCCqG
SM49BAMCA0cAMEQCIDA2DCQ9k1jlxAKgfb2Bm+g89eAkCx8nbgsOE3WLwU5mAiAy
oPW8PyFrB7RmpFmvufQssEJFcSP+2YjKwDtQD/8JNQ==
-----END CERTIFICATE-----
`

const ecdhKeyPem = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg26e2NB1N1WyMFKPa
SqXe+jKB7IsEQGI0iHA/gJni3hahRANCAATrV3GbxD7yZEz67fB+8OANa/LRaVBK
Emmx9VfvaQ1k7GYgRgvqWdgdHX398K0AgNNjK6l/3Zc0EK5Ga08Vyumn
-----END PRIVATE KEY-----
`

const deviceKeyPem = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAaMkbrhqPz+pbqNafW2AfNF+VJVl11pmVoIMz4iytbCoAoGCCqGSM49
AwEHoUQDQgAE/IRnCdWvzXHySTZ6ECcTxnqKoK8FkZ0lVF3oG0w1ihWnGX9fnxA6
/tXdOJMIhH2JcRMY8vOZFslCjAtJiCwaOQ==
-----END EC PRIVATE KEY-----
`
const (
	testEcdhCertFile  = "test_ecdh.cert.pem"
	testEcdhKeyFile   = "test_ecdh.key.pem"
	testDeviceKeyFile = "test_device.key.pem"
)

//Test ECDH key exchange and a symmetric cipher based on ECDH, with software based keys
func TestSoftEcdh(t *testing.T) {
	//Redirect ECDH cert/key files to test files
	ecdhCertFile = testEcdhCertFile
	ecdhKeyFile = testEcdhKeyFile

	err := ioutil.WriteFile(ecdhCertFile, []byte(ecdhCertPem), 0644)
	if err != nil {
		t.Errorf("Failed to create test certificate file: %v", err)
	}
	defer os.Remove(ecdhCertFile)

	err = ioutil.WriteFile(ecdhKeyFile, []byte(ecdhKeyPem), 0644)
	if err != nil {
		t.Errorf("Failed to create test key file: %v", err)
	}
	defer os.Remove(ecdhKeyFile)

	if err = testEcdhAES(); err != nil {
		t.Errorf("%v", err)
	}
}

//Test ECDH key exchange and a symmetric cipher based on ECDH, with software based keys
func TestGetPrivateKeyFromFile(t *testing.T) {
	err := ioutil.WriteFile(testEcdhKeyFile, []byte(ecdhKeyPem), 0644)
	if err != nil {
		t.Errorf("Failed to create test ecdh key file: %v", err)
	}
	defer os.Remove(ecdhKeyFile)

	err = ioutil.WriteFile(testDeviceKeyFile, []byte(deviceKeyPem), 0644)
	if err != nil {
		t.Errorf("Failed to create test device key file: %v", err)
	}
	defer os.Remove(testDeviceKeyFile)

	if _, err = getPrivateKeyFromFile(testEcdhKeyFile); err != nil {
		t.Errorf("%v", err)
	}

	if _, err = getPrivateKeyFromFile(testDeviceKeyFile); err != nil {
		t.Errorf("%v", err)
	}
}
