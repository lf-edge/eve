// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package scepclient_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cmd/scepclient"
)

var (
	oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
	oidExtensionRequest  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
)

// TestPrependChallengePassword verifies that PrependChallengePassword:
//   - produces a CSR whose self-signature validates,
//   - places challengePassword as the first attribute,
//   - places Extension Request (SAN) as the second attribute,
//   - preserves SAN entries from the original CSR.
func TestPrependChallengePassword(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	sanURI, _ := url.Parse("urn:serial:TEST123")
	template := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "test-device"},
		URIs:               []*url.URL{sanURI},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}

	fixedDER, err := scepclient.PrependChallengePassword(csrDER, "s3cret", x509.SHA256WithRSA, key)
	if err != nil {
		t.Fatalf("PrependChallengePassword: %v", err)
	}

	// Signature must validate.
	csr, err := x509.ParseCertificateRequest(fixedDER)
	if err != nil {
		t.Fatalf("parse fixed CSR: %v", err)
	}
	if err = csr.CheckSignature(); err != nil {
		t.Fatalf("signature invalid: %v", err)
	}

	// Parse raw attributes to verify ordering.
	type tbsCertReq struct {
		Raw           asn1.RawContent
		Version       int
		Subject       asn1.RawValue
		PublicKey     asn1.RawValue
		RawAttributes []asn1.RawValue `asn1:"tag:0"`
	}
	type certReq struct {
		Raw      asn1.RawContent
		TBS      tbsCertReq
		SigAlg   asn1.RawValue
		SigValue asn1.BitString
	}
	var req certReq
	if _, err = asn1.Unmarshal(fixedDER, &req); err != nil {
		t.Fatalf("unmarshal fixed CSR: %v", err)
	}
	attrs := req.TBS.RawAttributes
	if len(attrs) < 2 {
		t.Fatalf("expected at least 2 attributes, got %d", len(attrs))
	}

	attrOID := func(raw asn1.RawValue) asn1.ObjectIdentifier {
		var attr struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue `asn1:"set"`
		}
		if _, err := asn1.Unmarshal(raw.FullBytes, &attr); err != nil {
			t.Fatalf("unmarshal attribute: %v", err)
		}
		return attr.Type
	}

	if !attrOID(attrs[0]).Equal(oidChallengePassword) {
		t.Errorf("first attribute = %v, want challengePassword", attrOID(attrs[0]))
	}
	if !attrOID(attrs[1]).Equal(oidExtensionRequest) {
		t.Errorf("second attribute = %v, want extensionRequest", attrOID(attrs[1]))
	}

	// SAN URI must be preserved.
	if len(csr.URIs) != 1 || csr.URIs[0].String() != sanURI.String() {
		t.Errorf("SAN URIs = %v, want [%s]", csr.URIs, sanURI)
	}
}
