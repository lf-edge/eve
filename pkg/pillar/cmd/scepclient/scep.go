// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package scepclient

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512" // register SHA384 and SHA512 for CSR signing
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	eveconfig "github.com/lf-edge/eve-api/go/config"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	eveproxy "github.com/lf-edge/eve-api/go/proxy"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
	"google.golang.org/protobuf/proto"
)

func (c *SCEPClient) handleSCEPProfile(profile types.SCEPProfile, deleted bool) {
	var enrolledCert types.EnrolledCertificateStatus
	enrolledCertObj, err := c.pubEnrolledCertStatus.Get(profile.ProfileName)
	if err == nil && enrolledCertObj != nil {
		enrolledCert = enrolledCertObj.(types.EnrolledCertificateStatus)
	}

	if deleted {
		c.log.Noticef("Clearing EnrolledCertificateStatus for deleted SCEP profile %s",
			profile.ProfileName)
		if enrolledCert.CertFilepath != "" {
			if err = os.Remove(enrolledCert.CertFilepath); err != nil {
				c.log.Errorf(
					"Failed to remove certificate file %q for deleted SCEP profile %q: %v",
					enrolledCert.CertFilepath, profile.ProfileName, err)
			}
		}
		if enrolledCert.PrivateKeyFilepath != "" {
			if err = os.Remove(enrolledCert.PrivateKeyFilepath); err != nil {
				c.log.Errorf(
					"Failed to remove private key file %q for deleted SCEP profile %q: %v",
					enrolledCert.PrivateKeyFilepath, profile.ProfileName, err)
			}
		}
		if err = c.pubEnrolledCertStatus.Unpublish(profile.ProfileName); err != nil {
			c.log.Errorf("Failed to un-publish EnrolledCertificateStatus for profile %s",
				profile.ProfileName)
		}
		return
	}

	if enrolledCert.EnrollmentServerURL == profile.SCEPServerURL &&
		enrolledCert.CSRProfile.Equal(profile.CSRProfile) &&
		generics.EqualSets(enrolledCert.TrustAnchorFingerprints,
			trustAnchorFingerprints(profile.CACertPEM)) {
		// Certificate is already enrolled (or previously failed and will be
		// retried by retryAndStartRenew()), and the enrollment profile has not changed.
		return
	}

	c.log.Noticef("Processing created or modified SCEP profile %s",
		profile.ProfileName)

	// A new SCEP profile was added or an existing profile was modified by the user.
	// Reset the enrolled certificate state (in case it is not a zero value) to start
	// a fresh enrollment.
	enrolledCert.CertEnrollmentProfileName = profile.ProfileName
	enrolledCert.EnrollmentServerURL = profile.SCEPServerURL
	enrolledCert.TrustAnchorFingerprints = trustAnchorFingerprints(profile.CACertPEM)
	enrolledCert.CSRProfile = profile.CSRProfile
	enrolledCert.Error = types.ErrorDescription{}
	if profile.CSRProfile.RenewPeriodPercent != 0 {
		enrolledCert.RenewPeriodPercent = profile.CSRProfile.RenewPeriodPercent
	} else {
		enrolledCert.RenewPeriodPercent = defaultRenewPeriod
	}
	if profile.CSRProfile.KeyType != eveconfig.KeyType_KEY_TYPE_UNSPECIFIED {
		enrolledCert.KeyType = profile.CSRProfile.KeyType
	} else {
		enrolledCert.KeyType = defaultKeyType
	}
	hashAlgorithm := profile.CSRProfile.HashAlgorithm
	if hashAlgorithm != eveconfig.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		enrolledCert.HashAlgorithm = hashAlgorithm
	} else {
		enrolledCert.HashAlgorithm = defaultHashAlgorithm
	}
	enrolledCert.CertStatus = eveinfo.CertStatus_CERT_STATUS_UNSPECIFIED
	// Use nil cert to clear subject, issuer, SAN and other reported cert fields.
	c.populateCertStatus(&enrolledCert, nil)

	if enrolledCert.CertFilepath != "" {
		if err = os.Remove(enrolledCert.CertFilepath); err != nil {
			c.log.Errorf("Failed to remove obsolete certificate file %q "+
				"for modified SCEP profile %q: %v", enrolledCert.CertFilepath,
				profile.ProfileName, err)
		}
		enrolledCert.CertFilepath = ""
	}

	if enrolledCert.PrivateKeyFilepath != "" {
		if err = os.Remove(enrolledCert.PrivateKeyFilepath); err != nil {
			c.log.Errorf("Failed to remove obsolete private key file %q "+
				"for modified SCEP profile %q: %v", enrolledCert.PrivateKeyFilepath,
				profile.ProfileName, err)
		}
		enrolledCert.PrivateKeyFilepath = ""
	}

	if enrolledCert.CACertBundleFilepath != "" {
		if err = os.Remove(enrolledCert.CACertBundleFilepath); err != nil {
			c.log.Errorf("Failed to remove obsolete CA cert bundle %q "+
				"for modified SCEP profile %q: %v", enrolledCert.CACertBundleFilepath,
				profile.ProfileName, err)
		}
		enrolledCert.CACertBundleFilepath = ""
	}

	if profile.ParsingError.Error != "" {
		enrolledCert.CertStatus = eveinfo.CertStatus_CERT_STATUS_INVALID_CONFIG
		enrolledCert.Error = profile.ParsingError
		c.publishEnrolledCertStatus(enrolledCert)
		return
	}

	privateKey, err := c.makePrivateKey(enrolledCert.KeyType)
	if err != nil {
		err = fmt.Errorf("failed to generate private key: %v", err)
		enrolledCert.CertStatus = eveinfo.CertStatus_CERT_STATUS_ENROLLMENT_FAILED
		enrolledCert.Error.SetErrorDescription(types.ErrorDescription{Error: err.Error()})
		c.publishEnrolledCertStatus(enrolledCert)
		return
	}

	enrolledCert.PrivateKeyFilepath, err = c.savePrivateKey(profile.ProfileName, privateKey)
	if err != nil {
		enrolledCert.CertStatus = eveinfo.CertStatus_CERT_STATUS_ENROLLMENT_FAILED
		enrolledCert.Error.SetErrorDescription(types.ErrorDescription{Error: err.Error()})
		c.publishEnrolledCertStatus(enrolledCert)
		return
	}

	cert, caCerts, pending, err := c.enrollOrRenewCertificate(profile, nil, privateKey)
	if err != nil {
		enrolledCert.CertStatus = eveinfo.CertStatus_CERT_STATUS_ENROLLMENT_FAILED
		enrolledCert.Error.SetErrorDescription(types.ErrorDescription{Error: err.Error()})
		c.publishEnrolledCertStatus(enrolledCert)
		return
	}

	if pending {
		// No need to persist the SCEP transaction ID.
		// The transaction ID is deterministically derived from the certificate
		// public key (via SubjectKeyIdentifier). As long as the key is preserved,
		// the same transaction ID will be regenerated on retry.
		// Therefore, storing it separately is unnecessary.
		enrolledCert.CertStatus = eveinfo.CertStatus_CERT_STATUS_PENDING
		c.publishEnrolledCertStatus(enrolledCert)
		return
	}

	enrolledCert.CACertBundleFilepath, err = c.saveCACertBundle(profile.ProfileName, caCerts)
	if err != nil {
		enrolledCert.CertStatus = eveinfo.CertStatus_CERT_STATUS_ENROLLMENT_FAILED
		enrolledCert.Error.SetErrorDescription(types.ErrorDescription{Error: err.Error()})
		c.publishEnrolledCertStatus(enrolledCert)
		return
	}

	enrolledCert.CertFilepath, err = c.saveCertificate(profile.ProfileName, cert)
	if err != nil {
		enrolledCert.CertStatus = eveinfo.CertStatus_CERT_STATUS_ENROLLMENT_FAILED
		enrolledCert.Error.SetErrorDescription(types.ErrorDescription{Error: err.Error()})
		c.publishEnrolledCertStatus(enrolledCert)
		return
	}

	c.populateCertStatus(&enrolledCert, cert)
	enrolledCert.CertStatus = eveinfo.CertStatus_CERT_STATUS_AVAILABLE
	c.publishEnrolledCertStatus(enrolledCert)
}

// makePrivateKey generates a new private key for SCEP enrollment.
// Only RSA keys are currently supported. Even though the SCEP RFC allows
// non-encryption-capable keys (e.g., DSA or ECDSA) to be used with
// the CMS PasswordRecipientInfo mechanism (RFC3211) for PKCS#7 encryption,
// there is no open-source SCEP client that supports it, and many SCEP
// servers do not implement it either.
// As a result, ECDSA keys cannot be used for SCEP enrollment at this time.
func (c *SCEPClient) makePrivateKey(keyType eveconfig.KeyType) (SignerAndDecrypter, error) {
	switch keyType {
	case eveconfig.KeyType_KEY_TYPE_RSA_2048:
		return rsa.GenerateKey(rand.Reader, 2048)

	case eveconfig.KeyType_KEY_TYPE_RSA_3072:
		return rsa.GenerateKey(rand.Reader, 3072)

	case eveconfig.KeyType_KEY_TYPE_RSA_4096:
		return rsa.GenerateKey(rand.Reader, 4096)

	case eveconfig.KeyType_KEY_TYPE_ECDSA_P256,
		eveconfig.KeyType_KEY_TYPE_ECDSA_P384,
		eveconfig.KeyType_KEY_TYPE_ECDSA_P521:
		return nil, fmt.Errorf("ECDSA keys are not supported for SCEP enrollment " +
			"due to lack of PasswordRecipientInfo support")

	case eveconfig.KeyType_KEY_TYPE_UNSPECIFIED:
		return nil, errors.New("unspecified key type")

	default:
		return nil, fmt.Errorf("unsupported key type: %v", keyType)
	}
}

// enrollOrRenewCertificate performs SCEP certificate enrollment or renewal.
//
// If currentCert is nil, this is an initial enrollment: a CSR is generated,
// signed with a short-lived self-signed bootstrap certificate, and sent to the
// SCEP server via the controller proxy.
//
// If currentCert is not nil, this is a renewal: a CSR is generated and signed
// using the current certificate and its private key.
//
// The function returns the issued certificate and the CA certificate bundle
// (trust anchors + verified intermediate certs from the SCEP server) on success,
// or a boolean indicating whether the request is pending (SCEP PENDING status).
// Errors are returned if the operation fails or the SCEP response is invalid.
func (c *SCEPClient) enrollOrRenewCertificate(profile types.SCEPProfile,
	currentCert *x509.Certificate,
	privateKey SignerAndDecrypter) (cert *x509.Certificate, caCerts []*x509.Certificate, pending bool, err error) {
	if currentCert == nil {
		c.log.Noticef("Enrolling a new certificate for profile %s", profile.ProfileName)
	} else {
		c.log.Noticef("Renewing certificate for profile %s", profile.ProfileName)
	}

	// Decrypt challenge password (if configured).
	challengePassword, err := c.decryptChallengePassword(
		profile.EncryptedChallengePassword)
	if err != nil {
		return nil, nil, false, err
	}

	// Create CSR for the requested profile.
	csr, err := c.makeCSR(profile.CSRProfile, privateKey, challengePassword)
	if err != nil {
		return nil, nil, false, err
	}

	signerCert := currentCert
	if signerCert == nil {
		// No current certificate exists; create a short-lived self-signed certificate
		// to sign the initial PKCSReq for SCEP enrollment (bootstrap only).
		signerCert, err = c.makeSelfSignedCert(privateKey, csr)
		if err != nil {
			return nil, nil, false, err
		}
	}

	// Parse configured trust anchor CA certificates.
	// These are the root/intermediate CA certs from the SCEP profile configuration.
	var trustAnchors []*x509.Certificate
	for _, certBytes := range profile.CACertPEM {
		// Parsing errors should be unreachable because zedagent already validated
		// config, including trusted certificates.
		block, _ := pem.Decode(certBytes)
		if block == nil {
			c.log.Errorf("Failed to PEM-decode a configured SCEP CA cert")
			continue
		}
		if caCert, err := x509.ParseCertificate(block.Bytes); err == nil {
			trustAnchors = append(trustAnchors, caCert)
		} else {
			c.log.Errorf("Failed to parse a configured SCEP CA cert: %v", err)
		}
	}

	// Obtain CA certificates from the SCEP server via GetCACert operation.
	// The SCEP server may use an intermediate CA cert for signing/decryption
	// that is not in the profile's CACertPEM but is signed by one of the
	// trust anchor CAs.
	caCerts, err = c.getCACerts(profile, trustAnchors)
	if err != nil {
		return nil, nil, false, err
	}

	// Query SCEP server capabilities via GetCACaps operation.
	// This determines the supported encryption and hash algorithms.
	caps, err := c.getCACaps(profile)
	if err != nil {
		return nil, nil, false, err
	}

	// Set the content encryption algorithm based on server capabilities.
	// The pkcs7 library uses a global variable to select the encryption algorithm
	// for the PKCS#7 envelope.
	pkcs7.ContentEncryptionAlgorithm = caps.encryptionAlgorithm()

	// Verify that the hash algorithm required by the profile is supported
	// by the SCEP server.
	if err := caps.checkHashSupport(profile.CSRProfile.HashAlgorithm); err != nil {
		return nil, nil, false, err
	}

	// Build PKCSReq message template.
	var msgType scep.MessageType
	if currentCert != nil {
		msgType = scep.RenewalReq
	} else {
		msgType = scep.PKCSReq
	}
	pkiTemplate := &scep.PKIMessage{
		MessageType: msgType,
		Recipients:  caCerts,
		SignerKey:   privateKey,
		SignerCert:  signerCert,
	}
	if challengePassword != "" {
		pkiTemplate.CSRReqMessage = &scep.CSRReqMessage{
			ChallengePassword: challengePassword,
		}
	}

	reqMsg, err := scep.NewCSRRequest(csr, pkiTemplate,
		scep.WithCertsSelector(scep.EnciphermentCertsSelector()))
	if err != nil {
		err = fmt.Errorf("failed to create SCEP PKCSReq message: %w", err)
		return nil, nil, false, err
	}

	var respBytes []byte
	if profile.UseControllerProxy {
		respBytes, err = c.execPKIOperationOverProxy(profile, reqMsg)
	} else {
		respBytes, err = c.execPKIOperationDirectly(profile, reqMsg)
	}
	if err != nil {
		return nil, nil, false, err
	}

	// Parse and validate SCEP PKI message.
	respMsg, err := scep.ParsePKIMessage(respBytes, scep.WithCACerts(caCerts))
	if err != nil {
		if err.Error() == "pkcs7: No certificate for signer" {
			if betterErr := missingSignerCertsError(respBytes); betterErr != nil {
				return nil, nil, false, betterErr
			}
		}
		err = fmt.Errorf("failed to parse and validate SCEP PKI message: %w", err)
		return nil, nil, false, err
	}

	// Handle SCEP PKI status.
	switch respMsg.PKIStatus {
	case scep.FAILURE:
		err = fmt.Errorf("SCEP server responded with FAILURE status: %s",
			respMsg.FailInfo)
		return nil, nil, false, err

	case scep.PENDING:
		return nil, nil, true, nil
	}

	// Decrypt issued certificate envelope.
	if err = respMsg.DecryptPKIEnvelope(signerCert, privateKey); err != nil {
		err = fmt.Errorf("failed to decrypt SCEP certificate response envelope: %w", err)
		return nil, nil, false, err
	}

	if respMsg.CertRepMessage == nil || respMsg.CertRepMessage.Certificate == nil {
		err = fmt.Errorf("SCEP response did not contain an issued certificate")
		return nil, nil, false, err
	}

	// Merge in any trust anchors that the SCEP server did not return.
	for _, ta := range trustAnchors {
		alreadyPresent := false
		for _, vc := range caCerts {
			if ta.Equal(vc) {
				alreadyPresent = true
				break
			}
		}
		if !alreadyPresent {
			caCerts = append(caCerts, ta)
		}
	}
	return respMsg.CertRepMessage.Certificate, caCerts, false, nil
}

// colonHex formats a byte slice as colon-separated hex (e.g. "5e:1e:36:83"),
// matching the conventional serial number display used by openssl.
func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, ":")
}

// missingSignerCertsError attempts to parse the raw SCEP response and produce
// a detailed error listing the signer certificates that are missing from the
// provided CA certificate set. Returns nil if the response cannot be parsed.
func missingSignerCertsError(respBytes []byte) error {
	p7, err := pkcs7.Parse(respBytes)
	if err != nil {
		return nil
	}
	var missing []string
	for _, signer := range p7.Signers {
		ias := signer.IssuerAndSerialNumber
		serialHex := colonHex(ias.SerialNumber.Bytes())
		var issuer pkix.RDNSequence
		if _, err := asn1.Unmarshal(ias.IssuerName.FullBytes, &issuer); err == nil {
			var name pkix.Name
			name.FillFromRDNSequence(&issuer)
			missing = append(missing, fmt.Sprintf(
				"serial=%s, issuer=%q", serialHex, name))
		} else {
			missing = append(missing, fmt.Sprintf(
				"serial=%s, issuer=<unparsable>", serialHex))
		}
	}
	return fmt.Errorf("missing one or more CA certificates needed "+
		"to verify SCEP response signature; required signer certs: [%s]",
		strings.Join(missing, "; "))
}

// getCACerts retrieves CA certificates from the SCEP server using the GetCACert
// operation, verifies them against the configured trust anchors, and returns
// all successfully verified CA certificates.
// This is needed because the SCEP server may use an intermediate CA cert for
// signing/decryption that is not in the profile's CACertPEM.
func (c *SCEPClient) getCACerts(profile types.SCEPProfile,
	trustAnchors []*x509.Certificate) ([]*x509.Certificate, error) {

	var (
		respBytes   []byte
		contentType string
		err         error
	)
	if profile.UseControllerProxy {
		respBytes, contentType, err = c.getCACertOverProxy(profile)
	} else {
		respBytes, contentType, err = c.getCACertDirectly(profile)
	}
	if err != nil {
		return nil, fmt.Errorf("SCEP GetCACert failed: %w", err)
	}

	// Parse the response based on content type.
	// See RFC 8894, Section 4.1.1:
	//  - "application/x-x509-ca-cert": single DER-encoded certificate
	//  - "application/x-x509-ca-ra-cert": PKCS#7 degenerate certs-only message
	var serverCerts []*x509.Certificate
	switch {
	case strings.Contains(contentType, "application/x-x509-ca-ra-cert"):
		p7, err := pkcs7.Parse(respBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse GetCACert PKCS#7 response: %w", err)
		}
		serverCerts = p7.Certificates
	case strings.Contains(contentType, "application/x-x509-ca-cert"):
		cert, err := x509.ParseCertificate(respBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse GetCACert DER response: %w", err)
		}
		serverCerts = []*x509.Certificate{cert}
	default:
		// Some SCEP servers do not set a specific content type.
		// Try PKCS#7 first, then fall back to a single DER certificate.
		if p7, err := pkcs7.Parse(respBytes); err == nil {
			serverCerts = p7.Certificates
		} else if cert, err := x509.ParseCertificate(respBytes); err == nil {
			serverCerts = []*x509.Certificate{cert}
		} else {
			return nil, fmt.Errorf(
				"failed to parse GetCACert response (content-type %q)", contentType)
		}
	}

	// Log received CA certificates.
	for i, cert := range serverCerts {
		c.log.Noticef("SCEP GetCACert for profile %s [%d]: "+
			"subject=%q, issuer=%q, serial=%s, notBefore=%s, notAfter=%s",
			profile.ProfileName, i, cert.Subject, cert.Issuer,
			colonHex(cert.SerialNumber.Bytes()),
			cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}

	// Verify server-provided certs against trust anchors.
	verifiedCerts, err := c.verifyCACerts(serverCerts, trustAnchors)
	if err != nil {
		return nil, err
	}

	return verifiedCerts, nil
}

func (c *SCEPClient) getCACertDirectly(
	profile types.SCEPProfile) (respBytes []byte, contentType string, err error) {
	scepServerURL, err := url.Parse(profile.SCEPServerURL)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse SCEP server URL: %w", err)
	}

	query := scepServerURL.Query()
	query.Set("operation", "GetCACert")
	query.Set("message", profile.ProfileName)
	scepServerURL.RawQuery = query.Encode()

	ctx, cancel := c.httpClient.GetContextForAllIntfFunctions()
	retval, err := c.httpClient.SendOnAllIntf(
		ctx,
		scepServerURL.String(),
		nil, // nil body = HTTP GET
		controllerconn.RequestOptions{
			WithNetTracing: true,
			NetTraceFolder: types.NetTraceFolder,
			BailOnHTTPErr:  true,
			Iteration:      c.iteration,
		},
	)
	cancel()
	c.iteration++
	if err != nil {
		c.publishSCEPNetdump(retval.TracedReqs, false)
		return nil, "", fmt.Errorf("SCEP GetCACert request failed (HTTP status %d): %w",
			retval.Status, err)
	}

	if retval.HTTPResp != nil {
		contentType = retval.HTTPResp.Header.Get("Content-Type")
	}
	return retval.RespContents, contentType, nil
}

func (c *SCEPClient) getCACertOverProxy(
	profile types.SCEPProfile) (respBytes []byte, contentType string, err error) {
	proxyReq := &eveproxy.SCEPProxyRequest{
		ScepProfileName:  profile.ProfileName,
		Operation:        eveproxy.SCEPOperation_SCEP_OPERATION_GET_CA_CERT,
		HttpMethod:       eveproxy.HTTPMethod_HTTP_METHOD_GET,
		HttpHeaderFields: []*eveproxy.HTTPHeaderField{},
	}

	proxyReqBytes, err := proto.Marshal(proxyReq)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal SCEPProxyRequest: %w", err)
	}

	proxyURL := controllerconn.URLPathString(
		c.controllerHostname,
		c.devUUID,
		"proxy/scep",
	)

	ctx, cancel := c.httpClient.GetContextForAllIntfFunctions()
	retval, err := c.httpClient.SendOnAllIntf(
		ctx,
		proxyURL,
		bytes.NewBuffer(proxyReqBytes),
		controllerconn.RequestOptions{
			WithNetTracing: true,
			NetTraceFolder: types.NetTraceFolder,
			BailOnHTTPErr:  true,
			Iteration:      c.iteration,
		},
	)
	cancel()
	c.iteration++
	if err != nil {
		c.publishSCEPNetdump(retval.TracedReqs, false)
		return nil, "", fmt.Errorf("SCEP proxy GetCACert request failed (HTTP status %d): %w",
			retval.Status, err)
	}

	if err = c.httpClient.RemoveAndVerifyAuthContainer(&retval, false); err != nil {
		c.publishSCEPNetdump(retval.TracedReqs, false)
		return nil, "", fmt.Errorf(
			"failed to verify SCEP proxy GetCACert response authentication: %w", err)
	}

	proxyResp := &eveproxy.SCEPProxyResponse{}
	if err = proto.Unmarshal(retval.RespContents, proxyResp); err != nil {
		c.publishSCEPNetdump(retval.TracedReqs, false)
		return nil, "", fmt.Errorf("failed to unmarshal SCEPProxyResponse: %w", err)
	}

	if proxyResp.HttpStatusCode >= 400 {
		c.publishSCEPNetdump(retval.TracedReqs, false)
		const maxBody = 1024
		body := proxyResp.ErrorBody
		if len(body) > maxBody {
			body = body[:maxBody]
		}
		return nil, "", fmt.Errorf("SCEP server returned HTTP %d for GetCACert: %s",
			proxyResp.HttpStatusCode, strings.TrimSpace(string(body)))
	}

	// Extract content type from proxied response headers.
	for _, hf := range proxyResp.HttpHeaderFields {
		if strings.EqualFold(hf.Name, "Content-Type") {
			contentType = hf.Value
			break
		}
	}
	return proxyResp.Message, contentType, nil
}

// verifyCACerts verifies that each server-provided certificate is trusted,
// i.e. its chain leads to one of the trust anchors and the cert is currently valid.
// Certificates that are already in the trust anchors set are accepted without
// further chain verification.
// Certificates selected by EnciphermentCertsSelector (i.e. used for encryption)
// must verify or an error is returned. Non-selected certificates that fail
// verification are skipped with a warning — for example, a root CA above our
// intermediate trust anchor is not needed for encryption.
// Returns all verified certs.
func (c *SCEPClient) verifyCACerts(
	serverCerts, trustAnchors []*x509.Certificate) ([]*x509.Certificate, error) {
	trustPool := x509.NewCertPool()
	for _, ta := range trustAnchors {
		trustPool.AddCert(ta)
	}

	// Also build an intermediate pool from server certs themselves,
	// because the chain may include multiple intermediates.
	intermediatePool := x509.NewCertPool()
	for _, cert := range serverCerts {
		intermediatePool.AddCert(cert)
	}

	// Determine which certs are selected for encryption.
	selectedCerts := scep.EnciphermentCertsSelector().SelectCerts(serverCerts)
	isSelected := func(cert *x509.Certificate) bool {
		for _, sc := range selectedCerts {
			if cert.Equal(sc) {
				return true
			}
		}
		return false
	}

	var verified []*x509.Certificate
	now := time.Now()
	for _, cert := range serverCerts {
		certDesc := fmt.Sprintf("%q (serial %s)", cert.Subject,
			colonHex(cert.SerialNumber.Bytes()))

		// Check temporal validity.
		if now.Before(cert.NotBefore) {
			return nil, fmt.Errorf("SCEP CA cert %s is not yet valid "+
				"(notBefore=%s)", certDesc, cert.NotBefore.Format(time.RFC3339))
		}
		if now.After(cert.NotAfter) {
			return nil, fmt.Errorf("SCEP CA cert %s has expired "+
				"(notAfter=%s)", certDesc, cert.NotAfter.Format(time.RFC3339))
		}

		// Accept if this cert is already one of the trust anchors.
		isTrustAnchor := false
		for _, ta := range trustAnchors {
			if cert.Equal(ta) {
				isTrustAnchor = true
				break
			}
		}
		if isTrustAnchor {
			verified = append(verified, cert)
			continue
		}

		// Verify chain to a trust anchor.
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:         trustPool,
			Intermediates: intermediatePool,
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			if isSelected(cert) {
				return nil, fmt.Errorf("SCEP CA cert %s selected for encryption "+
					"is not trusted by the configured trust anchors: %w",
					certDesc, err)
			}
			c.log.Warnf("SCEP CA cert %s is not trusted by the configured trust "+
				"anchors. Skipping, not needed for encryption. If used by SCEP server "+
				"to sign PKI response, the signature verification will fail: %v",
				certDesc, err)
			continue
		}
		verified = append(verified, cert)
	}
	return verified, nil
}

// scepCaps represents the set of capabilities advertised by a SCEP server
// via the GetCACaps operation (see RFC 8894, Section 3.5.2).
type scepCaps struct {
	log *base.LogObject
	raw []string // raw capability strings as returned by the server
}

// parseGetCACapsResponse parses the plain-text GetCACaps response body.
// Each capability is on its own line.
func parseGetCACapsResponse(log *base.LogObject, body []byte) scepCaps {
	var caps []string
	for _, line := range strings.Split(string(body), "\n") {
		capability := strings.TrimSpace(line)
		if capability != "" {
			caps = append(caps, capability)
		}
	}
	return scepCaps{log: log, raw: caps}
}

func (caps scepCaps) has(capability string) bool {
	for _, c := range caps.raw {
		if strings.EqualFold(c, capability) {
			return true
		}
	}
	return false
}

// encryptionAlgorithm returns the best content encryption algorithm supported
// by the SCEP server. Prefers AES over DES3 over DES.
// Note: The pkcs7 library does not support Triple-DES for encryption,
// so when DES3 is advertised but AES is not, we fall back to DES-CBC
// and log a warning.
func (caps scepCaps) encryptionAlgorithm() int {
	if caps.has("AES") {
		caps.log.Noticef("SCEP: using AES-128-CBC content encryption")
		// RFC 8894, section 3.5.2., states that AES-128 CBC should be used when
		// "AES" is reported.
		return pkcs7.EncryptionAlgorithmAES128CBC
	}
	if caps.has("DES3") {
		caps.log.Warnf("SCEP server advertises DES3 but the pkcs7 library " +
			"does not support Triple-DES encryption; falling back to DES-CBC")
	}
	caps.log.Noticef("SCEP: using DES-CBC content encryption")
	return pkcs7.EncryptionAlgorithmDESCBC
}

// checkHashSupport verifies that the hash algorithm required by the SCEP profile
// is supported by the SCEP server capabilities. Returns an error describing the
// mismatch if the algorithm is not supported.
func (caps scepCaps) checkHashSupport(hashAlg eveconfig.HashAlgorithm) error {
	switch hashAlg {
	case eveconfig.HashAlgorithm_HASH_ALGORITHM_SHA256:
		if !caps.has("SHA-256") {
			return fmt.Errorf("SCEP server does not advertise SHA-256 support "+
				"(capabilities: %s); profile requires SHA-256",
				strings.Join(caps.raw, ", "))
		}
	case eveconfig.HashAlgorithm_HASH_ALGORITHM_SHA384:
		// SHA-384 is not a standard SCEP capability keyword; it falls under SHA-512 family.
		// Check for both SHA-384 and SHA-512.
		if !caps.has("SHA-384") && !caps.has("SHA-512") {
			return fmt.Errorf("SCEP server does not advertise SHA-384/SHA-512 support "+
				"(capabilities: %s); profile requires SHA-384",
				strings.Join(caps.raw, ", "))
		}
	case eveconfig.HashAlgorithm_HASH_ALGORITHM_SHA512:
		if !caps.has("SHA-512") {
			return fmt.Errorf("SCEP server does not advertise SHA-512 support "+
				"(capabilities: %s); profile requires SHA-512",
				strings.Join(caps.raw, ", "))
		}
	}
	return nil
}

// getCACaps queries the SCEP server for its capabilities using the GetCACaps
// operation. The response is a plain-text list of supported capabilities.
func (c *SCEPClient) getCACaps(profile types.SCEPProfile) (scepCaps, error) {
	var (
		respBytes []byte
		err       error
	)
	if profile.UseControllerProxy {
		respBytes, err = c.getCACapsOverProxy(profile)
	} else {
		respBytes, err = c.getCACapsDirect(profile)
	}
	if err != nil {
		return scepCaps{}, fmt.Errorf("SCEP GetCACaps failed: %w", err)
	}

	caps := parseGetCACapsResponse(c.log, respBytes)
	c.log.Noticef("SCEP GetCACaps for profile %s: [%s]",
		profile.ProfileName, strings.Join(caps.raw, ", "))
	return caps, nil
}

func (c *SCEPClient) getCACapsDirect(
	profile types.SCEPProfile) (respBytes []byte, err error) {
	scepServerURL, err := url.Parse(profile.SCEPServerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SCEP server URL: %w", err)
	}

	query := scepServerURL.Query()
	query.Set("operation", "GetCACaps")
	query.Set("message", profile.ProfileName)
	scepServerURL.RawQuery = query.Encode()

	ctx, cancel := c.httpClient.GetContextForAllIntfFunctions()
	retval, err := c.httpClient.SendOnAllIntf(
		ctx,
		scepServerURL.String(),
		nil, // nil body = HTTP GET
		controllerconn.RequestOptions{
			WithNetTracing: true,
			NetTraceFolder: types.NetTraceFolder,
			BailOnHTTPErr:  true,
			Iteration:      c.iteration,
		},
	)
	cancel()
	c.iteration++
	if err != nil {
		c.publishSCEPNetdump(retval.TracedReqs, false)
		return nil, fmt.Errorf("SCEP GetCACaps request failed (HTTP status %d): %w",
			retval.Status, err)
	}

	return retval.RespContents, nil
}

func (c *SCEPClient) getCACapsOverProxy(
	profile types.SCEPProfile) (respBytes []byte, err error) {
	proxyReq := &eveproxy.SCEPProxyRequest{
		ScepProfileName:  profile.ProfileName,
		Operation:        eveproxy.SCEPOperation_SCEP_OPERATION_GET_CA_CAPS,
		HttpMethod:       eveproxy.HTTPMethod_HTTP_METHOD_GET,
		HttpHeaderFields: []*eveproxy.HTTPHeaderField{},
	}

	proxyReqBytes, err := proto.Marshal(proxyReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SCEPProxyRequest: %w", err)
	}

	proxyURL := controllerconn.URLPathString(
		c.controllerHostname,
		c.devUUID,
		"proxy/scep",
	)

	ctx, cancel := c.httpClient.GetContextForAllIntfFunctions()
	retval, err := c.httpClient.SendOnAllIntf(
		ctx,
		proxyURL,
		bytes.NewBuffer(proxyReqBytes),
		controllerconn.RequestOptions{
			WithNetTracing: true,
			NetTraceFolder: types.NetTraceFolder,
			BailOnHTTPErr:  true,
			Iteration:      c.iteration,
		},
	)
	cancel()
	c.iteration++
	if err != nil {
		c.publishSCEPNetdump(retval.TracedReqs, false)
		return nil, fmt.Errorf("SCEP proxy GetCACaps request failed (HTTP status %d): %w",
			retval.Status, err)
	}

	if err = c.httpClient.RemoveAndVerifyAuthContainer(&retval, false); err != nil {
		c.publishSCEPNetdump(retval.TracedReqs, false)
		return nil, fmt.Errorf(
			"failed to verify SCEP proxy GetCACaps response authentication: %w", err)
	}

	proxyResp := &eveproxy.SCEPProxyResponse{}
	if err = proto.Unmarshal(retval.RespContents, proxyResp); err != nil {
		c.publishSCEPNetdump(retval.TracedReqs, false)
		return nil, fmt.Errorf("failed to unmarshal SCEPProxyResponse: %w", err)
	}

	if proxyResp.HttpStatusCode >= 400 {
		c.publishSCEPNetdump(retval.TracedReqs, false)
		const maxBody = 1024
		body := proxyResp.ErrorBody
		if len(body) > maxBody {
			body = body[:maxBody]
		}
		return nil, fmt.Errorf("SCEP server returned HTTP %d for GetCACaps: %s",
			proxyResp.HttpStatusCode, strings.TrimSpace(string(body)))
	}

	return proxyResp.Message, nil
}

func (c *SCEPClient) execPKIOperationOverProxy(profile types.SCEPProfile,
	req *scep.PKIMessage) (respBytes []byte, err error) {
	// Prepare proxy request to controller.
	proxyReq := &eveproxy.SCEPProxyRequest{
		ScepProfileName:  profile.ProfileName,
		Operation:        eveproxy.SCEPOperation_SCEP_OPERATION_PKI_MESSAGE,
		Message:          req.Raw,
		HttpMethod:       eveproxy.HTTPMethod_HTTP_METHOD_POST,
		HttpHeaderFields: []*eveproxy.HTTPHeaderField{}, // no extra headers required
	}

	proxyReqBytes, err := proto.Marshal(proxyReq)
	if err != nil {
		err = fmt.Errorf("failed to marshal SCEPProxyRequest: %w", err)
		return nil, err
	}

	proxyURL := controllerconn.URLPathString(
		c.controllerHostname,
		c.devUUID,
		"proxy/scep",
	)

	ctx, cancel := c.httpClient.GetContextForAllIntfFunctions()
	retval, err := c.httpClient.SendOnAllIntf(
		ctx,
		proxyURL,
		bytes.NewBuffer(proxyReqBytes),
		controllerconn.RequestOptions{
			WithNetTracing: true,
			NetTraceFolder: types.NetTraceFolder,
			BailOnHTTPErr:  true,
			Iteration:      c.iteration,
		},
	)
	cancel()
	c.iteration++
	if err != nil {
		c.publishSCEPNetdump(retval.TracedReqs, false)
		err = fmt.Errorf("SCEP proxy request failed (HTTP status %d): %w",
			retval.Status, err)
		return nil, err
	}

	// Verify controller authentication container.
	if err = c.httpClient.RemoveAndVerifyAuthContainer(&retval, false); err != nil {
		c.publishSCEPNetdump(retval.TracedReqs, false)
		err = fmt.Errorf("failed to verify SCEP proxy response authentication: %w", err)
		return nil, err
	}

	proxyResp := &eveproxy.SCEPProxyResponse{}
	if err = proto.Unmarshal(retval.RespContents, proxyResp); err != nil {
		c.publishSCEPNetdump(retval.TracedReqs, false)
		err = fmt.Errorf("failed to unmarshal SCEPProxyResponse: %w", err)
		return nil, err
	}

	// Check proxied HTTP status returned by SCEP server.
	if proxyResp.HttpStatusCode >= 400 {
		c.publishSCEPNetdump(retval.TracedReqs, false)
		const maxBody = 1024
		body := proxyResp.ErrorBody
		if len(body) > maxBody {
			body = body[:maxBody]
		}
		err = fmt.Errorf("SCEP server returned HTTP %d: %s",
			proxyResp.HttpStatusCode, strings.TrimSpace(string(body)))
		return nil, err
	}

	c.publishSCEPNetdump(retval.TracedReqs, true)
	return proxyResp.Message, nil
}

func (c *SCEPClient) execPKIOperationDirectly(profile types.SCEPProfile,
	req *scep.PKIMessage) (respBytes []byte, err error) {
	scepServerURL, err := url.Parse(profile.SCEPServerURL)
	if err != nil {
		// This should be unreachable. Zedagent validates SCEP server URL and SCEPClient
		// ignores SCEP profiles with invalid config.
		err = fmt.Errorf("failed to parse SCEP server URL: %w", err)
		return nil, err
	}

	query := scepServerURL.Query()
	query.Set("operation", "PKIOperation")
	scepServerURL.RawQuery = query.Encode()

	header := make(http.Header)
	header.Set("Content-Type", "application/x-pki-message")

	ctx, cancel := c.httpClient.GetContextForAllIntfFunctions()
	retval, err := c.httpClient.SendOnAllIntf(
		ctx,
		scepServerURL.String(),
		bytes.NewBuffer(req.Raw),
		controllerconn.RequestOptions{
			WithNetTracing: true,
			NetTraceFolder: types.NetTraceFolder,
			BailOnHTTPErr:  true,
			CustomHeader:   header,
			Iteration:      c.iteration,
		},
	)
	cancel()
	c.iteration++
	if err != nil {
		c.publishSCEPNetdump(retval.TracedReqs, false)
		err = fmt.Errorf("SCEP request failed (HTTP status %d): %w",
			retval.Status, err)
		return nil, err
	}

	c.publishSCEPNetdump(retval.TracedReqs, true)
	return retval.RespContents, nil
}

func (c *SCEPClient) decryptChallengePassword(
	encryptedPassword types.CipherBlockStatus) (string, error) {
	if !encryptedPassword.IsCipher {
		if c.cipherMetrics != nil {
			c.cipherMetrics.RecordFailure(c.log, types.NoData)
		}
		return "", nil
	}
	status, decBlock, err := cipher.GetCipherCredentials(
		&cipher.DecryptCipherContext{
			Log:                  c.log,
			AgentName:            agentName,
			AgentMetrics:         c.cipherMetrics,
			PubSubControllerCert: c.subControllerCert,
			PubSubEdgeNodeCert:   c.subEdgeNodeCert,
		},
		encryptedPassword)
	if err != nil {
		err = fmt.Errorf("failed to decrypt SCEP challenge password: %w", err)
		return "", err
	}
	if status.HasError() {
		err = fmt.Errorf("failed to decrypt SCEP challenge password: %s", status.Error)
		return "", err
	}
	return decBlock.SCEPChallengePassword, nil
}

// ASN.1 structures mirroring the Go stdlib x509 package internals,
// used to manipulate raw CSR bytes for attribute reordering.
type csrPublicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type csrTBSCertificateRequest struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     csrPublicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type csrCertificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             csrTBSCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type csrChallengePasswordAttribute struct {
	Type  asn1.ObjectIdentifier
	Value []string `asn1:"set"`
}

var oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

// PrependChallengePassword inserts the challengePassword attribute as the first
// attribute in the CSR DER, before the Extension Request attribute. Some SCEP
// servers require this ordering and reject CSRs where it appears after extensions.
func PrependChallengePassword(derBytes []byte, challenge string,
	sigAlgo x509.SignatureAlgorithm, key crypto.Signer) ([]byte, error) {
	var req csrCertificateRequest
	rest, err := asn1.Unmarshal(derBytes, &req)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing data after CSR")
	}

	attr := csrChallengePasswordAttribute{
		Type:  oidChallengePassword,
		Value: []string{challenge},
	}
	attrBytes, err := asn1.Marshal(attr)
	if err != nil {
		return nil, err
	}
	var rawAttr asn1.RawValue
	if _, err = asn1.Unmarshal(attrBytes, &rawAttr); err != nil {
		return nil, err
	}

	tbsCSR := csrTBSCertificateRequest{
		Version:       0,
		Subject:       req.TBSCSR.Subject,
		PublicKey:     req.TBSCSR.PublicKey,
		RawAttributes: append([]asn1.RawValue{rawAttr}, req.TBSCSR.RawAttributes...),
	}
	tbsBytes, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return nil, err
	}

	hashFunc, err := hashFuncForSignatureAlgorithm(sigAlgo)
	if err != nil {
		return nil, err
	}
	h := hashFunc.New()
	h.Write(tbsBytes)
	sig, err := key.Sign(rand.Reader, h.Sum(nil), hashFunc)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(csrCertificateRequest{
		TBSCSR:             tbsCSR,
		SignatureAlgorithm: req.SignatureAlgorithm,
		SignatureValue: asn1.BitString{
			Bytes:     sig,
			BitLength: len(sig) * 8,
		},
	})
}

func hashFuncForSignatureAlgorithm(sigAlgo x509.SignatureAlgorithm) (crypto.Hash, error) {
	switch sigAlgo {
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256:
		return crypto.SHA256, nil
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		return crypto.SHA384, nil
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported signature algorithm: %v", sigAlgo)
	}
}

func (c *SCEPClient) makeCSR(profile types.CSRProfile, privateKey SignerAndDecrypter,
	challengePassword string) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         profile.Subject.CommonName,
			Organization:       profile.Subject.Organization,
			OrganizationalUnit: profile.Subject.OrganizationalUnit,
			Country:            profile.Subject.Country,
			Province:           profile.Subject.State,
			Locality:           profile.Subject.Locality,
		},
		DNSNames:       profile.SAN.DNSNames,
		EmailAddresses: profile.SAN.EmailAddresses,
		IPAddresses:    profile.SAN.IPAddresses,
	}
	for _, uriStr := range profile.SAN.URIs {
		// url.Parse implements a generic RFC 3986 URI parser (despite the name).
		// The error is intentionally ignored here because the configuration
		// has already been validated by zedagent, and any invalid CSR profile
		// is skipped earlier by SCEPClient.
		uri, _ := url.Parse(uriStr)
		template.URIs = append(template.URIs, uri)
	}

	// Select Signature Algorithm
	hashAlg := profile.HashAlgorithm
	if hashAlg == eveconfig.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		hashAlg = defaultHashAlgorithm
	}
	keyType := profile.KeyType
	if keyType == eveconfig.KeyType_KEY_TYPE_UNSPECIFIED {
		keyType = defaultKeyType
	}
	sigAlg, err := selectSignatureAlgorithm(keyType, hashAlg)
	if err != nil {
		return nil, err
	}
	template.SignatureAlgorithm = sigAlg

	// Create CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}
	if challengePassword != "" {
		csrDER, err = PrependChallengePassword(csrDER, challengePassword, sigAlg, privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to add challenge password to CSR: %w", err)
		}
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated CSR: %w", err)
	}
	return csr, nil
}

// makeSelfSignedCert creates a short-lived self-signed certificate used
// exclusively for the initial SCEP enrollment (not for renewal).
// At this stage the client does not yet possess a CA-issued certificate,
// so this temporary certificate is used solely to sign the PKCS#7
// enrollment request and prove possession of the private key.
// It is not used for authentication, trust chaining, or any purpose beyond
// bootstrapping enrollment.
func (c *SCEPClient) makeSelfSignedCert(
	priv crypto.Signer, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 1)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "SCEP SIGNER",
			Organization: csr.Subject.Organization,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create self-signed SCEP bootstrap certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to parse generated self-signed SCEP bootstrap certificate: %w", err)
	}

	return cert, nil
}

// Run periodically to:
//   - Detect enrolled certificates or private keys that have been lost
//     (e.g. due to a disk error or vault re-creation) and trigger re-enrollment.
//   - Retry certificates that previously failed to enroll or renew.
//   - Re-run enrollment/renewal for certificates for which the SCEP server
//     returned PENDING (e.g. awaiting administrative approval).
//   - Check all enrolled certificates and initiate renewal attempts
//     for those that have entered their renewal window.
func (c *SCEPClient) retryAndStartRenew() {
	now := time.Now()

	for _, profileObj := range c.subSCEPProfile.GetAll() {
		profile := profileObj.(types.SCEPProfile)

		var enrolledCert types.EnrolledCertificateStatus
		enrolledCertObj, err := c.pubEnrolledCertStatus.Get(profile.ProfileName)
		if err == nil && enrolledCertObj != nil {
			enrolledCert = enrolledCertObj.(types.EnrolledCertificateStatus)
		}

		// If the enrolled certificate or its private key has been lost (e.g. due to
		// a disk error or vault re-creation), reset the certificate status to trigger
		// re-enrollment.
		if enrolledCert.CertFilepath != "" &&
			!fileutils.FileExists(c.log, enrolledCert.CertFilepath) {
			errMsg := fmt.Sprintf(
				"enrolled certificate file %s is missing (profile: %s)",
				enrolledCert.CertFilepath, profile.ProfileName)
			enrolledCert.CertStatus = eveinfo.CertStatus_CERT_STATUS_ENROLLMENT_FAILED
			enrolledCert.Error.SetErrorDescription(
				types.ErrorDescription{Error: errMsg})
			enrolledCert.CertFilepath = ""
			c.removeCACertBundle(&enrolledCert)
			c.populateCertStatus(&enrolledCert, nil)
			c.publishEnrolledCertStatus(enrolledCert) // for logging purposes
		}
		if enrolledCert.PrivateKeyFilepath != "" &&
			fileutils.DirExists(c.log, privateKeyDir) &&
			!fileutils.FileExists(c.log, enrolledCert.PrivateKeyFilepath) {
			errMsg := fmt.Sprintf(
				"private key file %s is missing (profile: %s)",
				enrolledCert.PrivateKeyFilepath, profile.ProfileName)
			enrolledCert.CertStatus = eveinfo.CertStatus_CERT_STATUS_ENROLLMENT_FAILED
			enrolledCert.Error.SetErrorDescription(
				types.ErrorDescription{Error: errMsg})
			enrolledCert.PrivateKeyFilepath = ""
			// Remove the orphaned certificate -- it is unusable without its private key.
			c.removeCACertBundle(&enrolledCert)
			if enrolledCert.CertFilepath != "" {
				_ = os.Remove(enrolledCert.CertFilepath)
				enrolledCert.CertFilepath = ""
			}
			c.populateCertStatus(&enrolledCert, nil)
			c.publishEnrolledCertStatus(enrolledCert) // for logging purposes
		}

		// Check if the certificate has expired (the device could have been powered
		// off for a long time). An expired certificate cannot be used to sign SCEP
		// renewal requests, so it must be re-enrolled from scratch.
		if enrolledCert.CertFilepath != "" &&
			!enrolledCert.ExpirationTimestamp.IsZero() &&
			enrolledCert.ExpirationTimestamp.Before(now) &&
			enrolledCert.CertStatus != eveinfo.CertStatus_CERT_STATUS_EXPIRED {
			c.log.Noticef("Certificate for profile %s has expired (expired at %v), "+
				"removing expired cert file %s",
				profile.ProfileName, enrolledCert.ExpirationTimestamp,
				enrolledCert.CertFilepath)
			_ = os.Remove(enrolledCert.CertFilepath)
			c.removeCACertBundle(&enrolledCert)
			enrolledCert.CertFilepath = ""
			enrolledCert.CertStatus = eveinfo.CertStatus_CERT_STATUS_EXPIRED
			c.publishEnrolledCertStatus(enrolledCert)
		}

		// Determine the next action.
		var enrollNewCert, renewCert bool

		switch enrolledCert.CertStatus {
		case eveinfo.CertStatus_CERT_STATUS_UNSPECIFIED:
			enrollNewCert = true

		case eveinfo.CertStatus_CERT_STATUS_AVAILABLE:
			// Determine if certificate is inside the renewal window.
			validity := enrolledCert.ExpirationTimestamp.Sub(enrolledCert.IssueTimestamp)
			if validity > 0 {
				renewPercent := enrolledCert.RenewPeriodPercent
				renewTime := enrolledCert.IssueTimestamp.Add(
					time.Duration(int64(validity) * int64(renewPercent) / 100),
				)
				if now.After(renewTime) {
					renewCert = true
				}
			}

		case eveinfo.CertStatus_CERT_STATUS_PENDING:
			// If no cert exists yet → enrollment pending.
			// If cert exists → renewal pending.
			if enrolledCert.CertFilepath == "" {
				enrollNewCert = true
			} else {
				renewCert = true
			}

		case eveinfo.CertStatus_CERT_STATUS_EXPIRED:
			// An expired certificate cannot be used to sign SCEP renewal requests.
			// Re-enroll from scratch (reusing the existing private key).
			enrollNewCert = true

		case eveinfo.CertStatus_CERT_STATUS_ENROLLMENT_FAILED:
			enrollNewCert = true

		case eveinfo.CertStatus_CERT_STATUS_RENEWAL_FAILED:
			renewCert = true

		case eveinfo.CertStatus_CERT_STATUS_INVALID_CONFIG:
			// Do nothing with this SCEP profile.
		}

		if !renewCert && !enrollNewCert {
			continue
		}

		// Set failure and pending states to use if the enrollment or renewal
		// operation executed below fails or is still in progress.
		var failureState, pendingState eveinfo.CertStatus
		if enrollNewCert {
			failureState = eveinfo.CertStatus_CERT_STATUS_ENROLLMENT_FAILED
			pendingState = eveinfo.CertStatus_CERT_STATUS_PENDING
		} else if renewCert {
			failureState = eveinfo.CertStatus_CERT_STATUS_RENEWAL_FAILED
			pendingState = eveinfo.CertStatus_CERT_STATUS_RENEWAL_PENDING
		}

		// Load or generate private key
		var privateKey SignerAndDecrypter

		if enrolledCert.PrivateKeyFilepath != "" {
			privateKey, err = c.loadPrivateKey(enrolledCert.PrivateKeyFilepath)
			if err != nil {
				enrolledCert.CertStatus = failureState
				errStr := fmt.Sprintf("failed to load private key: %v", err)
				enrolledCert.Error.SetErrorDescription(
					types.ErrorDescription{Error: errStr},
				)
				c.publishEnrolledCertStatus(enrolledCert)
				continue
			}
		} else {
			privateKey, err = c.makePrivateKey(enrolledCert.KeyType)
			if err != nil {
				enrolledCert.CertStatus = failureState
				errStr := fmt.Sprintf("failed to generate private key: %v", err)
				enrolledCert.Error.SetErrorDescription(
					types.ErrorDescription{Error: errStr},
				)
				c.publishEnrolledCertStatus(enrolledCert)
				continue
			}

			enrolledCert.PrivateKeyFilepath, err = c.savePrivateKey(
				profile.ProfileName, privateKey)
			if err != nil {
				enrolledCert.CertStatus = failureState
				errStr := fmt.Sprintf("failed to save private key: %v", err)
				enrolledCert.Error.SetErrorDescription(
					types.ErrorDescription{Error: errStr},
				)
				c.publishEnrolledCertStatus(enrolledCert)
				continue
			}
		}

		// Enrollment or renewal
		var cert *x509.Certificate
		var caCerts []*x509.Certificate
		var pending bool

		if enrollNewCert {
			cert, caCerts, pending, err = c.enrollOrRenewCertificate(
				profile, nil, privateKey)
		} else {
			// Load currently enrolled certificate for signing the SCEP renewal request.
			var currentCert *x509.Certificate
			currentCert, err = c.loadCertificate(enrolledCert.CertFilepath)
			if err != nil {
				enrolledCert.CertStatus = failureState
				errMsg := fmt.Sprintf("failed to load current certificate: %v", err)
				enrolledCert.Error.SetErrorDescription(
					types.ErrorDescription{Error: errMsg},
				)
				c.publishEnrolledCertStatus(enrolledCert)
				continue
			}
			cert, caCerts, pending, err = c.enrollOrRenewCertificate(
				profile, currentCert, privateKey)
		}

		if err != nil {
			enrolledCert.CertStatus = failureState
			enrolledCert.Error.SetErrorDescription(
				types.ErrorDescription{Error: err.Error()},
			)
			c.publishEnrolledCertStatus(enrolledCert)
			continue
		}

		if pending {
			enrolledCert.CertStatus = pendingState
			c.publishEnrolledCertStatus(enrolledCert)
			continue
		}

		// Save CA certificate bundle.
		caBundlePath, err := c.saveCACertBundle(profile.ProfileName, caCerts)
		if err != nil {
			enrolledCert.CertStatus = failureState
			errMsg := fmt.Sprintf("failed to save CA cert bundle: %v", err)
			enrolledCert.Error.SetErrorDescription(
				types.ErrorDescription{Error: errMsg},
			)
			c.publishEnrolledCertStatus(enrolledCert)
			continue
		}
		enrolledCert.CACertBundleFilepath = caBundlePath

		// Save new certificate
		certFilePath, err := c.saveCertificate(profile.ProfileName, cert)
		if err != nil {
			enrolledCert.CertStatus = failureState
			errMsg := fmt.Sprintf("failed to save certificate: %v", err)
			enrolledCert.Error.SetErrorDescription(
				types.ErrorDescription{Error: errMsg},
			)
			c.publishEnrolledCertStatus(enrolledCert)
			continue
		}
		enrolledCert.CertFilepath = certFilePath

		c.populateCertStatus(&enrolledCert, cert)
		enrolledCert.CertStatus = eveinfo.CertStatus_CERT_STATUS_AVAILABLE
		enrolledCert.Error = types.ErrorDescription{}
		c.publishEnrolledCertStatus(enrolledCert)
	}
}

// populateCertStatus copies certificate-derived fields from cert
// into the provided EnrolledCertificateStatus.
// It does not modify renewal settings, status, key type, hash algorithm or file paths.
func (c *SCEPClient) populateCertStatus(status *types.EnrolledCertificateStatus,
	cert *x509.Certificate) {
	if status == nil {
		return
	}

	if cert == nil {
		status.Subject = types.CertDistinguishedName{}
		status.Issuer = types.CertDistinguishedName{}
		status.SAN = types.CertSubjectAlternativeName{}
		status.IssueTimestamp = time.Time{}
		status.ExpirationTimestamp = time.Time{}
		status.SHA256Fingerprint = ""
		return
	}

	status.Subject = pkixNameToCertDistinguishedName(cert.Subject)
	status.Issuer = pkixNameToCertDistinguishedName(cert.Issuer)

	status.SAN = types.CertSubjectAlternativeName{
		DNSNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
		IPAddresses:    cert.IPAddresses,
	}
	for _, uri := range cert.URIs {
		status.SAN.URIs = append(status.SAN.URIs, uri.String())
	}

	status.IssueTimestamp = cert.NotBefore
	status.ExpirationTimestamp = cert.NotAfter

	sum := sha256.Sum256(cert.Raw)
	status.SHA256Fingerprint = hex.EncodeToString(sum[:])
}

func (c *SCEPClient) publishEnrolledCertStatus(status types.EnrolledCertificateStatus) {
	oldStatus, err := c.pubEnrolledCertStatus.Get(status.Key())
	if err == nil && oldStatus != nil {
		c.log.Functionf("Publishing EnrolledCertStatus(%s) update: %s",
			status.Key(), cmp.Diff(oldStatus, status))
	} else {
		c.log.Functionf("Publishing new EnrolledCertStatus(%s): %+v",
			status.Key(), status)
	}
	err = c.pubEnrolledCertStatus.Publish(status.Key(), status)
	if err != nil {
		c.log.Errorf("Failed to publish EnrolledCertificateStatus for profile %s",
			status.CertEnrollmentProfileName)
	}
}

// Publish netdump containing traces of executed SCEP requests.
func (c *SCEPClient) publishSCEPNetdump(
	tracedReqs []netdump.TracedNetRequest, success bool) {
	netDumper := c.netDumper
	if netDumper == nil {
		return
	}
	topic := netDumpConfigOKTopic
	if !success {
		topic = netDumpConfigFailTopic
	}
	filename, err := netDumper.Publish(topic, types.NetTraceFolder, tracedReqs...)
	if err != nil {
		c.log.Warnf("Failed to publish netdump for topic %s: %v", topic, err)
	} else {
		c.log.Noticef("Published netdump for topic %s: %s", topic, filename)
	}
}

func (c *SCEPClient) savePrivateKey(profileName string,
	key SignerAndDecrypter) (path string, err error) {
	if key == nil {
		return "", errors.New("nil private key")
	}
	if err = os.MkdirAll(privateKeyDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create private key directory: %w", err)
	}

	derBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	})

	path = c.getPrivateKeyFilePath(profileName)
	if err = os.WriteFile(path, pemBytes, 0600); err != nil {
		return "", fmt.Errorf("failed to write private key: %w", err)
	}
	return path, nil
}

func (c *SCEPClient) loadPrivateKey(path string) (SignerAndDecrypter, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %q: %w", path, err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block in private key file %q", path)
	}

	// Parse PKCS#8 (this is how savePrivateKey writes it)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key in %q: %w", path, err)
	}

	// Make sure it is RSA (only supported)
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		err = fmt.Errorf(
			"unsupported private key type in %q: only RSA is supported", path)
		return nil, err
	}
	return rsaKey, nil
}

func (c *SCEPClient) saveCertificate(profileName string,
	cert *x509.Certificate) (path string, err error) {
	if cert == nil {
		return "", errors.New("nil certificate")
	}
	if err = os.MkdirAll(certDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create cert directory: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	path = c.getCertFilePath(profileName)
	if err = os.WriteFile(path, pemBytes, 0644); err != nil {
		return "", fmt.Errorf("failed to write certificate: %w", err)
	}
	return path, nil
}

func (c *SCEPClient) saveCACertBundle(profileName string,
	caCerts []*x509.Certificate) (path string, err error) {
	if len(caCerts) == 0 {
		return "", errors.New("empty CA certificate bundle")
	}
	if err = os.MkdirAll(certDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create cert directory: %w", err)
	}

	var pemData []byte
	for _, cert := range caCerts {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	path = c.getCACertBundleFilePath(profileName)
	if err = os.WriteFile(path, pemData, 0644); err != nil {
		return "", fmt.Errorf("failed to write CA cert bundle: %w", err)
	}
	return path, nil
}

func (c *SCEPClient) removeCACertBundle(enrolledCert *types.EnrolledCertificateStatus) {
	if enrolledCert.CACertBundleFilepath != "" {
		_ = os.Remove(enrolledCert.CACertBundleFilepath)
		enrolledCert.CACertBundleFilepath = ""
	}
}

func (c *SCEPClient) loadCertificate(path string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %q: %w", path, err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM block in certificate file %q", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate in %q: %w", path, err)
	}
	return cert, nil
}

// trustAnchorFingerprints returns a SHA-256 fingerprint (hex-encoded) for each
// trust anchor certificate PEM. The returned slice has one entry per cert,
// making it easy to see how many trust anchors are configured and to compare
// sets regardless of order using generics.EqualSets.
func trustAnchorFingerprints(caCertPEM [][]byte) []string {
	fingerprints := make([]string, 0, len(caCertPEM))
	for _, certPEM := range caCertPEM {
		h := sha256.Sum256(certPEM)
		fingerprints = append(fingerprints, hex.EncodeToString(h[:]))
	}
	return fingerprints
}

// sanitizeProfileName returns a file-name-safe representation of the profile
// name using URL-safe base64 encoding (no padding).
func sanitizeProfileName(name string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(name))
}

func (c *SCEPClient) getCertFilePath(profileName string) string {
	return filepath.Join(certDir, sanitizeProfileName(profileName)+"-cert.pem")
}

func (c *SCEPClient) getCACertBundleFilePath(profileName string) string {
	return filepath.Join(certDir, sanitizeProfileName(profileName)+"-ca-bundle.pem")
}

func (c *SCEPClient) getPrivateKeyFilePath(profileName string) string {
	return filepath.Join(privateKeyDir, sanitizeProfileName(profileName)+"-key.pem")
}

func pkixNameToCertDistinguishedName(name pkix.Name) types.CertDistinguishedName {
	return types.CertDistinguishedName{
		CommonName:         name.CommonName,
		SerialNumber:       name.SerialNumber,
		Organization:       name.Organization,
		OrganizationalUnit: name.OrganizationalUnit,
		Country:            name.Country,
		State:              name.Province,
		Locality:           name.Locality,
	}
}

func selectSignatureAlgorithm(keyType eveconfig.KeyType,
	hashAlg eveconfig.HashAlgorithm) (x509.SignatureAlgorithm, error) {

	switch keyType {
	case eveconfig.KeyType_KEY_TYPE_RSA_2048,
		eveconfig.KeyType_KEY_TYPE_RSA_3072,
		eveconfig.KeyType_KEY_TYPE_RSA_4096:

		switch hashAlg {
		case eveconfig.HashAlgorithm_HASH_ALGORITHM_SHA256:
			return x509.SHA256WithRSA, nil
		case eveconfig.HashAlgorithm_HASH_ALGORITHM_SHA384:
			return x509.SHA384WithRSA, nil
		case eveconfig.HashAlgorithm_HASH_ALGORITHM_SHA512:
			return x509.SHA512WithRSA, nil
		default:
			return 0, fmt.Errorf("unsupported hash algorithm for RSA: %v", hashAlg)
		}

	case eveconfig.KeyType_KEY_TYPE_ECDSA_P256,
		eveconfig.KeyType_KEY_TYPE_ECDSA_P384,
		eveconfig.KeyType_KEY_TYPE_ECDSA_P521:

		switch hashAlg {
		case eveconfig.HashAlgorithm_HASH_ALGORITHM_SHA256:
			return x509.ECDSAWithSHA256, nil
		case eveconfig.HashAlgorithm_HASH_ALGORITHM_SHA384:
			return x509.ECDSAWithSHA384, nil
		case eveconfig.HashAlgorithm_HASH_ALGORITHM_SHA512:
			return x509.ECDSAWithSHA512, nil
		default:
			return 0, fmt.Errorf("unsupported hash algorithm for ECDSA: %v", hashAlg)
		}

	default:
		return 0, fmt.Errorf("unsupported key type: %v", keyType)
	}
}
