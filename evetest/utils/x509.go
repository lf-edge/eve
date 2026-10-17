// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"

	"github.com/lf-edge/eve-api/go/certs"
	"github.com/lf-edge/eve-api/go/evecommon"
)

// CertToPEM returns the PEM encoding of the certificate.
func CertToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// ECDSAPrivateKeyToPEM returns the PEM encoding of an ECDSA private key in PKCS#8 format.
func ECDSAPrivateKeyToPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

// ConvertToZCert converts X.509 certificate to ZCert proto message.
//
// The hash must be encoded exactly as Adam encodes it when serving the same
// certificate from /certs -- SHA-256 over the trimmed PEM, truncated to 16 bytes,
// flagged SHA256_16BYTES -- because pillar keys types.ControllerCert on
// hex(CertHash): any other encoding would make the device hold one certificate
// under two keys.
func ConvertToZCert(cert *x509.Certificate, certType certs.ZCertType) *certs.ZCert {
	return &certs.ZCert{
		Cert:     CertToPEM(cert),
		CertHash: ControllerCertHash(cert)[:16],
		HashAlgo: evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_16BYTES,
		Type:     certType,
	}
}

// ValidatePEMCerts parses PEM-encoded certificates and validates them as X.509.
// If expectSingle is true, exactly one PEM block is expected; otherwise multiple
// PEM blocks are allowed (e.g., for proxy or V2 TLS certs).
func ValidatePEMCerts(pemData []byte, expectSingle bool) ([]*pem.Block, error) {
	var blocks []*pem.Block
	rest := pemData
	for len(rest) > 0 {
		block, r := pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("invalid PEM block")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("invalid x509 certificate: %w", err)
		}
		blocks = append(blocks, block)
		rest = r
	}

	if expectSingle && len(blocks) != 1 {
		return nil, fmt.Errorf("expected exactly 1 PEM block, got %d", len(blocks))
	}
	return blocks, nil
}

// ValidatePEMPrivateKeyECDSA parses and validates a PEM-encoded ECDSA private key.
// Exactly one PEM block must be present. The key may be encoded either as
// PKCS#8 ("PRIVATE KEY") or legacy EC ("EC PRIVATE KEY").
func ValidatePEMPrivateKeyECDSA(pemData []byte) error {
	var found bool
	rest := pemData

	for len(rest) > 0 {
		block, r := pem.Decode(rest)
		if block == nil {
			return fmt.Errorf("invalid PEM block")
		}

		if found {
			return fmt.Errorf(
				"multiple PEM blocks found; expected exactly one ECDSA private key")
		}

		var parsed any
		var err error

		switch block.Type {
		case "PRIVATE KEY":
			// PKCS#8
			parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("invalid PKCS#8 private key: %w", err)
			}
		case "EC PRIVATE KEY":
			// Legacy EC key
			parsed, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("invalid EC private key: %w", err)
			}
		default:
			return fmt.Errorf("unexpected PEM block type %q", block.Type)
		}

		if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
			return fmt.Errorf("private key is not ECDSA")
		}
		found = true
		rest = r
	}

	if !found {
		return fmt.Errorf("no ECDSA private key found in PEM data")
	}
	return nil
}

// GenCARoot generates a self-signed RSA root CA certificate.
func GenCARoot() (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"lf-edge"},
			CommonName:   "Adam Root CA",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert, err := generateCertificate(template, template, &key.PublicKey, key)
	return cert, key, err
}

// GenServerCertElliptic generates an ECDSA server certificate signed by the given CA.
func GenServerCertElliptic(
	caCert *x509.Certificate, caKey *rsa.PrivateKey, serial *big.Int,
	ip []net.IP, dns []string, cn string,
) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"lf-edge"},
			CommonName:   cn,
		},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: ip,
		DNSNames:    dns,
	}

	cert, err := generateCertificate(template, caCert, &key.PublicKey, caKey)
	return cert, key, err
}

// generateCertificate creates and parses an X.509 certificate.
func generateCertificate(
	template, parent *x509.Certificate,
	publicKey, privateKey any,
) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

// certAndKeyPEM returns the PEM encodings of a certificate and its private key
// in the on-disk form expected by the Adam controller: RSA keys as PKCS#8
// ("PRIVATE KEY"), ECDSA keys as SEC 1 ("EC PRIVATE KEY").
func certAndKeyPEM(crt *x509.Certificate, key any) (certPEM, keyPEM []byte, err error) {
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw})
	if certPEM == nil {
		return nil, nil, fmt.Errorf("failed to PEM-encode certificate")
	}

	var block *pem.Block
	switch k := key.(type) {
	case *rsa.PrivateKey:
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal key to PKCS #8: %w", err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal EC key: %w", err)
		}
		block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %T", key)
	}
	keyPEM = pem.EncodeToMemory(block)
	if keyPEM == nil {
		return nil, nil, fmt.Errorf("failed to PEM-encode key")
	}
	return certPEM, keyPEM, nil
}

// OutputCertAndKey writes an X.509 certificate and private key to disk in PEM format.
func OutputCertAndKey(
	crt *x509.Certificate, key any, certFile string, keyFile string,
) error {
	certPEM, keyPEM, err := certAndKeyPEM(crt, key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return fmt.Errorf("failed to write cert file %s: %w", certFile, err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("failed to write key file %s: %w", keyFile, err)
	}
	return nil
}

// OutputCertAndKeyAtomic is OutputCertAndKey for a keypair that is replaced while
// a reader is running: the Adam controller re-reads the signing certificate and
// key on every signed response, and the encryption certificate on every /certs
// request and config-hash computation, so a truncate-then-write would let it read
// a half-written or empty file. The encryption *key* is read only at startup,
// which is why the mismatch window below concerns the signing pair alone.
//
// The certificate and the key are separate files and cannot be swapped as one, so
// a request landing between the two renames sees a mismatched signing pair. Adam
// detects that itself -- it loads the pair through tls.X509KeyPair, whose
// public-key equality check fails -- and answers HTTP 500, which the device
// retries on its next poll. The check is symmetric, so the write order does not
// change the outcome; the key is renamed first only to follow the convention of
// installing a secret before the certificate that advertises it.
//
// Both files are fully staged before either is published, so the mismatch is
// transient (bounded by one rename) rather than permanent: nothing that can fail
// for a resource reason -- creating, writing, fsyncing or chmodding a temp file --
// happens once the first rename has landed.
func OutputCertAndKeyAtomic(
	crt *x509.Certificate, key any, certFile string, keyFile string,
) error {
	certPEM, keyPEM, err := certAndKeyPEM(crt, key)
	if err != nil {
		return err
	}
	keyTmp, err := stageFileAtomic(keyFile, keyPEM, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write key file %s: %w", keyFile, err)
	}
	// Both are no-ops after a successful rename.
	defer func() { _ = os.Remove(keyTmp) }()
	certTmp, err := stageFileAtomic(certFile, certPEM, 0o644)
	if err != nil {
		return fmt.Errorf("failed to write cert file %s: %w", certFile, err)
	}
	defer func() { _ = os.Remove(certTmp) }()

	if err := os.Rename(keyTmp, keyFile); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %w", keyTmp, keyFile, err)
	}
	if err := os.Rename(certTmp, certFile); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %w", certTmp, certFile, err)
	}
	return nil
}

// WriteFileAtomic writes data into a temporary file in the same directory as
// path, fsyncs it and renames it over path. A concurrent reader therefore
// observes either the old or the new content, never a partially written file.
// The mode of the resulting file is perm regardless of the umask.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmpName, err := stageFileAtomic(path, data, perm)
	if err != nil {
		return err
	}
	// A no-op after a successful rename.
	defer func() { _ = os.Remove(tmpName) }()

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %w", tmpName, path, err)
	}
	return nil
}

// stageFileAtomic writes data into a temporary file next to path, fsyncs it and
// gives it mode perm, leaving a rename over path as the only remaining step.
// The temp file is removed on every error path; on success the caller owns it.
func stageFileAtomic(path string, data []byte, perm os.FileMode) (string, error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	fail := func(err error) (string, error) {
		_ = os.Remove(tmpName)
		return "", err
	}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fail(fmt.Errorf("failed to write %s: %w", tmpName, err))
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fail(fmt.Errorf("failed to sync %s: %w", tmpName, err))
	}
	if err := tmp.Close(); err != nil {
		return fail(fmt.Errorf("failed to close %s: %w", tmpName, err))
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return fail(fmt.Errorf("failed to set mode %o on %s: %w", perm, tmpName, err))
	}
	return tmpName, nil
}

// computeEcdsaSignature signs the payload using the given ECDSA private key
// and returns the signature as a fixed-length r||s byte slice.
func computeEcdsaSignature(payload []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	var signature []byte
	var rsCombErr error

	r, s, err := ecdsa.Sign(rand.Reader, key, payload)
	if err != nil {
		return nil, err
	}
	signature, rsCombErr = rsCombinedBytes(r.Bytes(), s.Bytes(), &key.PublicKey)
	if rsCombErr != nil {
		return nil, rsCombErr
	}
	return signature, nil
}

// rsCombinedBytes combines the ECDSA r and s values into a fixed-length
// byte slice (r || s), left-padding each to the curve size.
func rsCombinedBytes(rBytes, sBytes []byte, pubKey *ecdsa.PublicKey) ([]byte, error) {
	keySize, err := ecdsaKeyBytes(pubKey)
	if err != nil {
		return nil, fmt.Errorf("RSCombinedBytes: ecdsa key bytes error %v", err)
	}
	rsize := len(rBytes)
	ssize := len(sBytes)
	if rsize > keySize || ssize > keySize {
		return nil, fmt.Errorf("RSCombinedBytes: error. keySize %v, rSize %v, sSize %v",
			keySize, rsize, ssize)
	}

	// basically the size is 32 bytes. the r and s needs to be both left padded
	// to two 32 bytes slice into a single signature buffer
	buffer := make([]byte, keySize*2)
	startPos := keySize - rsize
	copy(buffer[startPos:], rBytes)
	startPos = keySize*2 - ssize
	copy(buffer[startPos:], sBytes)
	return buffer[:], nil
}

// ecdsaKeyBytes returns the byte length required to represent an ECDSA
// key for the given curve.
func ecdsaKeyBytes(pubKey *ecdsa.PublicKey) (int, error) {
	curveBits := pubKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}
	if keyBytes%8 > 0 {
		return 0, fmt.Errorf("ecdsa pubkey size error, curveBits %v", curveBits)
	}
	return keyBytes, nil
}

// calculateSymmetricKeyForEcdhAES derives a symmetric key using ECDH between
// the device certificate's public key and the controller's private key.
func calculateSymmetricKeyForEcdhAES(
	devECDHCert *x509.Certificate, controllerECDHKey *ecdsa.PrivateKey) ([]byte, error) {
	var devPublicKey *ecdsa.PublicKey
	switch k := devECDHCert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		devPublicKey = k
	default:
		return nil, fmt.Errorf("unsupported device public key type: %T", k)
	}

	// Multiply privateKey key with devPublic key.
	X, Y := elliptic.P256().Params().ScalarMult(
		devPublicKey.X, devPublicKey.Y, controllerECDHKey.D.Bytes())

	symmetricKey, err := sha256FromECPoint(X, Y, devPublicKey)
	if err != nil {
		return nil, err
	}
	return symmetricKey[:], nil
}

// sha256FromECPoint derives a 256-bit key by hashing the combined X and Y
// coordinates of an elliptic-curve point.
func sha256FromECPoint(X, Y *big.Int, pubKey *ecdsa.PublicKey) ([32]byte, error) {
	var sha [32]byte
	bytes, err := rsCombinedBytes(X.Bytes(), Y.Bytes(), pubKey)
	if err != nil {
		return sha, fmt.Errorf("Error occurred while combining bytes for ECPoints: %v", err)
	}
	return sha256.Sum256(bytes), nil
}
