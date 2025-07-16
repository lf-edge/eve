// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"fmt"
	"net"
	"os"
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
func ConvertToZCert(cert *x509.Certificate, certType certs.ZCertType) *certs.ZCert {
	certPEM := CertToPEM(cert)
	shaOfCert := sha256.Sum256(certPEM)
	zcert := &certs.ZCert{}
	zcert.Cert = certPEM
	zcert.CertHash = shaOfCert[:]
	zcert.Type = certType
	return zcert
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

// OutputCertAndKey writes an X.509 certificate and private key to disk in PEM format.
func OutputCertAndKey(
	crt *x509.Certificate, key any, certFile string, keyFile string,
) error {
	cf, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to create cert file %s: %w", certFile, err)
	}
	defer cf.Close()

	err = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw})
	if err != nil {
		return fmt.Errorf("failed to PEM-encode certificate: %w", err)
	}

	kf, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create key file %s: %w", keyFile, err)
	}
	defer kf.Close()

	switch k := key.(type) {
	case *rsa.PrivateKey:
		b, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return fmt.Errorf("failed to marshal key to PKCS #8: %w", err)
		}
		err = pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: b})
		if err != nil {
			return fmt.Errorf("failed to PEM-encode key: %w", err)
		}
		return nil

	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return fmt.Errorf("failed to marshal key to PKCS #8: %w", err)
		}
		err = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
		if err != nil {
			return fmt.Errorf("failed to PEM-encode key: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
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
