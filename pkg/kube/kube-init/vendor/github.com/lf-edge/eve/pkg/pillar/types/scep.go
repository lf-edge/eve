// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"
	"time"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
)

// SCEPProfile defines configuration required to enroll a device certificate
// using SCEP (Simple Certificate Enrollment Protocol).
//
// It specifies:
//   - How to reach the SCEP server (directly or via controller proxy)
//   - Trust anchors used to validate SCEP responses
//   - Parameters for CSR generation
type SCEPProfile struct {
	// ProfileName is a user-assigned logical identifier for this
	// certificate enrollment configuration.
	ProfileName string

	// Full SCEP server URL, including scheme, host, and path.
	// Example: https://ca.example.com/scep
	SCEPServerURL string

	// UseControllerProxy determines how SCEP traffic is routed:
	//   - true:  Requests are sent via the controller-provided SCEP proxy.
	//   - false: The device connects directly to SCEPServerURL.
	UseControllerProxy bool

	// Encrypted SCEP challenge password.
	EncryptedChallengePassword CipherBlockStatus

	// CACertPEM contains the trusted CA certificate chain in PEM format.
	//
	// The chain is used for:
	//   - Validating the CA signature on SCEP responses
	//   - Encrypting the symmetric key in the PKCS#7 enrollment request
	//     (certificates capable of key encryption will receive a copy)
	CACertPEM [][]byte `json:"pubsub-large-ProxyCertPEM"` //nolint:tagliatelle

	// CSRProfile defines parameters used to generate the Certificate Signing Request.
	CSRProfile CSRProfile

	// ParsingError indicates if SCEP profile parsing failed.
	ParsingError ErrorDescription
}

// Key returns the pubsub message key for SCEPProfile instance.
func (p SCEPProfile) Key() string {
	return p.ProfileName
}

// CSRProfile defines parameters used to construct a Certificate Signing Request (CSR)
// and control certificate renewal behavior.
type CSRProfile struct {
	// Subject specifies the X.509 Distinguished Name (DN) for the certificate.
	Subject CertDistinguishedName

	// SAN specifies Subject Alternative Name extensions for the certificate.
	SAN CertSubjectAlternativeName

	// RenewPeriodPercent defines when renewal should be attempted,
	// expressed as a percentage of the certificate validity period.
	// Example: 80 means renewal will start after 80% of the lifetime.
	// If unset (zero), a system-defined default may be applied.
	RenewPeriodPercent uint8

	// KeyType specifies the algorithm and parameters used to generate
	// the private key
	KeyType eveconfig.KeyType

	// HashAlgorithm specifies the hash function used for:
	//   - CSR signing
	//   - SCEP message signing
	HashAlgorithm eveconfig.HashAlgorithm
}

// Equal returns true if two CSRProfile values are equivalent.
// Used to detect configuration changes that require certificate re-enrollment.
func (p CSRProfile) Equal(other CSRProfile) bool {
	return p.Subject.Equal(other.Subject) &&
		p.SAN.Equal(other.SAN) &&
		p.RenewPeriodPercent == other.RenewPeriodPercent &&
		p.KeyType == other.KeyType &&
		p.HashAlgorithm == other.HashAlgorithm
}

// CertDistinguishedName represents selected X.509 Distinguished Name (DN) attributes.
// This structure includes commonly used fields but does not attempt
// to model the full ASN.1 DN grammar.
type CertDistinguishedName struct {
	CommonName         string
	SerialNumber       string
	Organization       []string
	OrganizationalUnit []string
	Country            []string
	State              []string
	Locality           []string
}

// Equal returns true if two CertDistinguishedName values are equivalent.
// Multi-valued RDN components are compared as order-independent sets.
func (n CertDistinguishedName) Equal(other CertDistinguishedName) bool {
	return n.CommonName == other.CommonName &&
		n.SerialNumber == other.SerialNumber &&
		generics.EqualSets(n.Organization, other.Organization) &&
		generics.EqualSets(n.OrganizationalUnit, other.OrganizationalUnit) &&
		generics.EqualSets(n.Country, other.Country) &&
		generics.EqualSets(n.State, other.State) &&
		generics.EqualSets(n.Locality, other.Locality)
}

// CertSubjectAlternativeName represents X.509 Subject Alternative Name (SAN) extensions.
type CertSubjectAlternativeName struct {
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []string
}

// Equal returns true if two CertSubjectAlternativeName values are equivalent.
// All SAN entries are compared as order-independent sets.
func (n CertSubjectAlternativeName) Equal(other CertSubjectAlternativeName) bool {
	return generics.EqualSets(n.DNSNames, other.DNSNames) &&
		generics.EqualSets(n.EmailAddresses, other.EmailAddresses) &&
		generics.EqualSetsFn(n.IPAddresses, other.IPAddresses, netutils.EqualIPs) &&
		generics.EqualSets(n.URIs, other.URIs)
}

// EnrolledCertificateStatus represents the runtime status of a certificate
// obtained via a certificate enrollment protocol (currently SCEP).
// This structure reflects the certificate actually installed on the device,
// including cryptographic parameters, validity, and storage location.
type EnrolledCertificateStatus struct {
	// Certificate enrollment profile used to obtain this certificate.
	CertEnrollmentProfileName string

	// Certificate Signing Request (CSR) profile used to enroll this certificate.
	// Persisted as part of EnrolledCertificateStatus to detect changes in the
	// enrollment configuration. If the CSR profile differs from the one currently
	// defined in the enrollment profile, the certificate must be re-enrolled.
	CSRProfile CSRProfile

	// URL of the enrollment server used to obtain this certificate.
	// Currently only SCEP servers are supported.
	// Persisted as part of EnrolledCertificateStatus to detect changes
	// to the configured server endpoint. If the server URL changes,
	// the certificate must be re-enrolled against the new server.
	EnrollmentServerURL string

	// TrustAnchorFingerprints contains SHA-256 fingerprints (hex-encoded) of
	// the trust anchor CA certificates from the enrollment profile.
	// One entry per configured trust anchor certificate.
	// Used to detect when the configured trust anchors change, which
	// requires re-enrollment.
	TrustAnchorFingerprints []string

	// Error indicates if certificate enrollment/renewal failed or
	// the enrollment profile config is invalid.
	Error ErrorDescription

	Subject CertDistinguishedName
	Issuer  CertDistinguishedName
	SAN     CertSubjectAlternativeName

	// Certificate renewal settings.
	// Published in the status in case the user left this unset in the CSR
	// and EVE therefore picked the default value.
	RenewPeriodPercent uint8

	// Key algorithm and parameters used to generate the private key.
	KeyType eveconfig.KeyType

	// Hash algorithm used for signing operations
	// (CSR generation, SCEP messages, etc.).
	HashAlgorithm eveconfig.HashAlgorithm

	// Certificate validity period.
	IssueTimestamp      time.Time
	ExpirationTimestamp time.Time

	// SHA-256 fingerprint of the certificate (hex-encoded).
	SHA256Fingerprint string

	// Current status of the certificate as observed by the device.
	CertStatus eveinfo.CertStatus

	// CertFilepath is the filesystem path to the installed certificate (PEM).
	CertFilepath string

	// CACertBundleFilepath is the filesystem path to the PEM-encoded CA cert bundle.
	CACertBundleFilepath string

	// PrivateKeyFilepath is the filesystem path to the associated private key (PEM).
	// The private key is stored in the vault for protection.
	PrivateKeyFilepath string
}

// Key returns the pubsub message key for EnrolledCertificateStatus instance.
func (s EnrolledCertificateStatus) Key() string {
	return s.CertEnrollmentProfileName
}

// Equivalent returns true if two EnrolledCertificateStatus values are equivalent,
// ignoring transient error information. This is used to detect configuration
// or status changes that may require re-enrollment or certificate update,
// without considering enrollment failures.
func (s EnrolledCertificateStatus) Equivalent(other EnrolledCertificateStatus) bool {
	return s.CertEnrollmentProfileName == other.CertEnrollmentProfileName &&
		s.CSRProfile.Equal(other.CSRProfile) &&
		s.EnrollmentServerURL == other.EnrollmentServerURL &&
		generics.EqualSets(s.TrustAnchorFingerprints, other.TrustAnchorFingerprints) &&
		s.Subject.Equal(other.Subject) &&
		s.Issuer.Equal(other.Issuer) &&
		s.SAN.Equal(other.SAN) &&
		s.RenewPeriodPercent == other.RenewPeriodPercent &&
		s.KeyType == other.KeyType &&
		s.HashAlgorithm == other.HashAlgorithm &&
		s.IssueTimestamp.Equal(other.IssueTimestamp) &&
		s.ExpirationTimestamp.Equal(other.ExpirationTimestamp) &&
		s.SHA256Fingerprint == other.SHA256Fingerprint &&
		s.CertStatus == other.CertStatus &&
		s.CertFilepath == other.CertFilepath &&
		s.CACertBundleFilepath == other.CACertBundleFilepath &&
		s.PrivateKeyFilepath == other.PrivateKeyFilepath
}
