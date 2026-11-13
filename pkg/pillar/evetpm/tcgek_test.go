// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
)

// certFor returns a certificate for pub, signed by a throwaway CA.
func certFor(t *testing.T, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	ca, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:  pkix.Name{CommonName: "EK"},
		NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, ca)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestReadTCGEK(t *testing.T) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		t.Skipf("TPM not available: %v", err)
	}
	defer rw.Close()

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		alg      tpm2.Algorithm
		template tpm2.Public
	}{{tpm2.AlgRSA, DefaultEkTemplate}, {tpm2.AlgECC, tcgEKTemplateECC}} {
		pub, err := ReadTCGEK(rw, tc.alg, nil)
		if err != nil {
			t.Fatalf("%v: %v", tc.alg, err)
		}
		if !pub.MatchesTemplate(tc.template) {
			t.Errorf("%v: EK does not match the TCG template", tc.alg)
		}
		key, err := pub.Key()
		if err != nil {
			t.Fatal(err)
		}
		again, err := ReadTCGEK(rw, tc.alg, certFor(t, key))
		if err != nil {
			t.Fatalf("%v: with its own certificate: %v", tc.alg, err)
		}
		againKey, _ := again.Key()
		if !key.(interface{ Equal(crypto.PublicKey) bool }).Equal(againKey) {
			t.Errorf("%v: EK differs between derivations", tc.alg)
		}
		if _, err := ReadTCGEK(rw, tc.alg, certFor(t, &other.PublicKey)); !errors.Is(err, errEKCertMismatch) {
			t.Errorf("%v: certificate for another key: got %v, want %v", tc.alg, err, errEKCertMismatch)
		}
	}

	// EVE's TpmEKHdl is an owner-hierarchy key, so it must not be the EK.
	rsaEK, _ := ReadTCGEK(rw, tpm2.AlgRSA, nil)
	eveEK, _, _, err := tpm2.ReadPublic(rw, TpmEKHdl)
	if err == nil {
		k1, _ := rsaEK.Key()
		k2, _ := eveEK.Key()
		if k1.(*rsa.PublicKey).Equal(k2) {
			t.Errorf("TCG EK equals the key at %#x", uint32(TpmEKHdl))
		}
	}

	if _, err := ReadTCGEK(rw, tpm2.AlgSHA256, nil); err == nil {
		t.Error("no error for an algorithm without a TCG EK template")
	}
}
