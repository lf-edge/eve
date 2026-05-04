// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"
	"testing"
	"time"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/stretchr/testify/assert"
)

// CertDistinguishedName.Equal

func TestCertDistinguishedNameEqual(t *testing.T) {
	n1 := CertDistinguishedName{
		CommonName:         "test",
		SerialNumber:       "123",
		Organization:       []string{"Org1", "Org2"},
		OrganizationalUnit: []string{"OU1"},
		Country:            []string{"US"},
		State:              []string{"CA"},
		Locality:           []string{"SF"},
	}
	n2 := n1
	assert.True(t, n1.Equal(n2))

	// Order-independent for multi-value fields
	n2.Organization = []string{"Org2", "Org1"}
	assert.True(t, n1.Equal(n2))

	n2.CommonName = "other"
	assert.False(t, n1.Equal(n2))

	n2 = n1
	n2.SerialNumber = "456"
	assert.False(t, n1.Equal(n2))

	n2 = n1
	n2.Country = []string{"DE"}
	assert.False(t, n1.Equal(n2))
}

// CertSubjectAlternativeName.Equal

func TestCertSubjectAlternativeNameEqual(t *testing.T) {
	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")

	s1 := CertSubjectAlternativeName{
		DNSNames:       []string{"a.example.com", "b.example.com"},
		EmailAddresses: []string{"user@example.com"},
		IPAddresses:    []net.IP{ip1, ip2},
		URIs:           []string{"spiffe://cluster/ns/svc"},
	}
	s2 := s1
	assert.True(t, s1.Equal(s2))

	// Order-independent DNS
	s2.DNSNames = []string{"b.example.com", "a.example.com"}
	assert.True(t, s1.Equal(s2))

	s2.DNSNames = []string{"c.example.com"}
	assert.False(t, s1.Equal(s2))

	s2 = s1
	s2.EmailAddresses = []string{"other@example.com"}
	assert.False(t, s1.Equal(s2))

	s2 = s1
	s2.IPAddresses = []net.IP{ip1}
	assert.False(t, s1.Equal(s2))

	s2 = s1
	s2.URIs = []string{"spiffe://other"}
	assert.False(t, s1.Equal(s2))
}

// CSRProfile.Equal

func TestCSRProfileEqual(t *testing.T) {
	p1 := CSRProfile{
		Subject:            CertDistinguishedName{CommonName: "device"},
		RenewPeriodPercent: 80,
		KeyType:            eveconfig.KeyType_KEY_TYPE_ECDSA_P256,
		HashAlgorithm:      eveconfig.HashAlgorithm_HASH_ALGORITHM_SHA256,
	}
	p2 := p1
	assert.True(t, p1.Equal(p2))

	p2.RenewPeriodPercent = 50
	assert.False(t, p1.Equal(p2))

	p2 = p1
	p2.KeyType = eveconfig.KeyType_KEY_TYPE_RSA_2048
	assert.False(t, p1.Equal(p2))

	p2 = p1
	p2.HashAlgorithm = eveconfig.HashAlgorithm_HASH_ALGORITHM_SHA512
	assert.False(t, p1.Equal(p2))

	p2 = p1
	p2.Subject.CommonName = "other"
	assert.False(t, p1.Equal(p2))
}

// EnrolledCertificateStatus.Equivalent

func TestEnrolledCertificateStatusEquivalent(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s1 := EnrolledCertificateStatus{
		CertEnrollmentProfileName: "profile1",
		EnrollmentServerURL:       "https://scep.example.com",
		TrustAnchorFingerprints:   []string{"abc123", "def456"},
		RenewPeriodPercent:        80,
		IssueTimestamp:            now,
		ExpirationTimestamp:       now.Add(365 * 24 * time.Hour),
		SHA256Fingerprint:         "deadbeef",
		CertStatus:                eveinfo.CertStatus_CERT_STATUS_AVAILABLE,
		CertFilepath:              "/certs/cert.pem",
		CACertBundleFilepath:      "/certs/ca.pem",
		PrivateKeyFilepath:        "/vault/key.pem",
	}
	s2 := s1
	assert.True(t, s1.Equivalent(s2))

	// Error field is intentionally ignored
	s2.Error = ErrorDescription{Error: "enrollment failed"}
	assert.True(t, s1.Equivalent(s2))

	s2 = s1
	s2.CertEnrollmentProfileName = "other"
	assert.False(t, s1.Equivalent(s2))

	s2 = s1
	s2.EnrollmentServerURL = "https://other.example.com"
	assert.False(t, s1.Equivalent(s2))

	s2 = s1
	s2.TrustAnchorFingerprints = []string{"abc123"}
	assert.False(t, s1.Equivalent(s2))

	s2 = s1
	s2.SHA256Fingerprint = "cafebabe"
	assert.False(t, s1.Equivalent(s2))

	s2 = s1
	s2.CertStatus = eveinfo.CertStatus_CERT_STATUS_EXPIRED
	assert.False(t, s1.Equivalent(s2))

	s2 = s1
	s2.CertFilepath = "/other/cert.pem"
	assert.False(t, s1.Equivalent(s2))
}

// SCEPProfile.Key / EnrolledCertificateStatus.Key

func TestSCEPProfileKey(t *testing.T) {
	p := SCEPProfile{ProfileName: "myprofile"}
	assert.Equal(t, "myprofile", p.Key())
}

func TestEnrolledCertificateStatusKey(t *testing.T) {
	s := EnrolledCertificateStatus{CertEnrollmentProfileName: "enroll1"}
	assert.Equal(t, "enroll1", s.Key())
}
