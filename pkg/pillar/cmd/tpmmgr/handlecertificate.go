// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package tpmmgr

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/api/go/evecommon"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// update the device generated certificates on pubsub
func publishEveNodeCertificates(ctx *tpmMgrContext) error {

	// ECDH Certificate
	certType := evecommon.ZCertType_Z_CERT_TYPE_DEVICE_ECDH_EXCHANGE
	if err := publishEveNodeCertificate(ctx, certType); err != nil {
		return err
	}

	// TBD:XXX for attest and others
	return nil
}

// generate/publish certificate, of a given type
func publishEveNodeCertificate(ctx *tpmMgrContext,
	certType evecommon.ZCertType) error {

	// check and update the certificate of a given type
	if updateEveNodeCertificate(ctx, certType) {
		return nil
	}

	// First Time, generate/publish

	// check for device certificate
	deviceCert, err := checkForDeviceCert()
	if err != nil || deviceCert == nil {
		log.Errorf("EveNode Certificate error:%v", err)
		return nil
	}

	// TPM is enabled
	if etpm.IsTpmEnabled() {
		return createEveNodeCertificateOnTpm(ctx, certType, deviceCert)
	}
	// create soft Ecdh Certificate
	return createEveNodeCertificateSoft(ctx, certType)
}

// create the certificate on Tpm
func createEveNodeCertificateOnTpm(ctx *tpmMgrContext,
	certType evecommon.ZCertType, deviceCert *x509.Certificate) error {

	switch certType {
	// of ECDH Type
	case evecommon.ZCertType_Z_CERT_TYPE_DEVICE_ECDH_EXCHANGE:
		return createEveNodeEcdhCerteOnTpm(ctx, deviceCert)

	// TBD:XXX create attest certificate, others, if any
	default:
		errStr := fmt.Sprintf("Certificate type: invalid")
		log.Errorf(errStr)
		return errors.New(errStr)
	}
}

// create the ecdh template
func createEcdhSoftTemplate() x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	notBefore := time.Now()
	// twenty years
	notAfter := notBefore.AddDate(20, 0, 0)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"Santa Clara"},
			Organization: []string{"Zededa, Inc"},
			CommonName:   "Cipher Block",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	return template
}

func createEveNodeCertificateSoft(ctx *tpmMgrContext,
	certType evecommon.ZCertType) error {

	/// not ECDH type return
	if certType != evecommon.ZCertType_Z_CERT_TYPE_DEVICE_ECDH_EXCHANGE {
		errStr := fmt.Sprintf("not ecdh certificate type")
		log.Errorf(errStr)
		return errors.New(errStr)
	}

	// create the ecdh certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		errStr := fmt.Sprintf("curve get fail, %v", err)
		log.Errorf(errStr)
		return errors.New(errStr)
	}
	publicKey := priv.PublicKey
	template := createEcdhSoftTemplate()

	derBytes, err := x509.CreateCertificate(rand.Reader,
		&template, &template, publicKey, priv)
	if err != nil {
		errStr := fmt.Sprintf("certificate create fail, %v", err)
		log.Errorf(errStr)
		return errors.New(errStr)
	}

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	certBytes := pem.EncodeToMemory(certBlock)
	if certBytes == nil {
		errStr := fmt.Sprintf("PEM Encode error: empty bytes")
		log.Errorf(errStr)
		return errors.New(errStr)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		errStr := fmt.Sprintf("certificate marshal fail, %v", err)
		log.Errorf(errStr)
		return errors.New(errStr)
	}

	keyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}

	keyBytes := pem.EncodeToMemory(keyBlock)
	if keyBytes == nil {
		errStr := fmt.Sprintf("PEM Encode error: empty bytes")
		log.Errorf(errStr)
		return errors.New(errStr)
	}

	// now publish
	algo := evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_16BYTES
	origin := types.CERT_ORIGIN_EVE_NODE_SOFTWARE
	var handle tpmutil.Handle
	prepareEvenNodeCertConfig(ctx, algo, certType, origin,
		handle, certBytes, keyBytes)
	return nil
}

// reead and publish Ecdh certificate
func createEveNodeEcdhCerteOnTpm(ctx *tpmMgrContext,
	deviceCert *x509.Certificate) error {

	certType := evecommon.ZCertType_Z_CERT_TYPE_DEVICE_ECDH_EXCHANGE

	log.Info("TPM: Create Ecdh Certificatee")

	// open TPM
	rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
	if err != nil {
		errStr := fmt.Sprintf("TPM: Open error, %v", err)
		log.Errorf(errStr)
		return errors.New(errStr)
	}

	// close on return
	defer rw.Close()

	// TBD:XXX handle certificate handle, appropriatelyy
	ecdhKey, _, _, err := tpm2.ReadPublic(rw, TpmEcdhKeyHdl)
	if err != nil {
		errStr := fmt.Sprintf("TPM: Read Pulic Key error, %v", err)
		log.Errorf(errStr)
		return errors.New(errStr)
	}

	publicKey, err := tpmKeyToEccKey(ecdhKey)
	if err != nil {
		errStr := fmt.Sprintf("TPM: Key to Ecc Key error, %v", err)
		log.Errorf(errStr)
		return errors.New(errStr)
	}

	tpmPrivKey := etpm.TpmPrivateKey{}
	template := *deviceCert

	tpmPrivKey.PublicKey = tpmPrivKey.Public()
	template.SerialNumber = big.NewInt(123456789)
	cert, err := x509.CreateCertificate(rand.Reader,
		&template, deviceCert, publicKey, tpmPrivKey)
	if err != nil {
		errStr := fmt.Sprintf("TPM: X509 cert create error, %v", err)
		log.Errorf(errStr)
		return errors.New(errStr)
	}

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}
	certBytes := pem.EncodeToMemory(certBlock)
	if certBytes == nil {
		errStr := fmt.Sprintf("PEM Encode error: empty bytes")
		log.Errorf(errStr)
		return errors.New(errStr)
	}

	algo := evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_16BYTES
	origin := types.CERT_ORIGIN_EVE_NODE_TPM
	handle := TpmEcdhKeyHdl
	prepareEvenNodeCertConfig(ctx, algo, certType, origin, handle, certBytes, []byte{})
	return nil
}

// generic book-keeping routines

// check and update a cerificate, from /config to pubsub
func updateEveNodeCertificate(ctx *tpmMgrContext, certType evecommon.ZCertType) bool {

	// check for the certificate, of given type
	if lookupEveNodeCertificate(ctx, certType, []byte{}) != nil {
		return true
	}

	//the /config entry exists, convert to persist pubsub
	// and remove the /config entry
	switch certType {
	case evecommon.ZCertType_Z_CERT_TYPE_DEVICE_ECDH_EXCHANGE:
		if etpm.FileExists(ecdhCertFile) {
			certBytes, err := getCertificateDataFromFile(ecdhCertFile)
			if err == nil {
				algo := evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_16BYTES
				origin := types.CERT_ORIGIN_EVE_NODE_TPM
				handle := TpmEcdhKeyHdl
				if !etpm.IsTpmEnabled() {
					// Error case, no non-tpm old device still
				}
				prepareEvenNodeCertConfig(ctx, algo, certType,
					origin, handle, certBytes, []byte{})
			}
			// delete old stuff
			os.Remove(ecdhCertFile)
			return true
		}
	default:
		return false
	}
	return false
}

// read the certificate data from file
func getCertificateDataFromFile(certPath string) ([]byte, error) {
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		errStr := fmt.Sprintf("getCertificateDataFromFile failed: %v",
			err)
		log.Error(errStr)
		return []byte{}, errors.New(errStr)
	}
	return certBytes, nil
}

// calculate the hash for a block
func computeHash(cert []byte, algo evecommon.HashAlgorithm) ([]byte, error) {
	h := sha256.New()
	h.Write(cert)
	hash := h.Sum(nil)
	switch algo {
	case evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_16BYTES:
		return hash[:16], nil
	case evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_32BYTES:
		return hash, nil
	default:
		return []byte{}, fmt.Errorf("Unsupported cert hash type: %d\n", algo)
	}
}

// check for device certificate in /config
func checkForDeviceCert() (*x509.Certificate, error) {
	// the device certificate is still not ready, return
	clientCertBytes, err := ioutil.ReadFile(types.DeviceCertName)
	if err != nil {
		log.Errorf("EveNode Certificate is absent")
		return nil, err
	}

	// validate the device certificate
	block, _ := pem.Decode(clientCertBytes)
	if block == nil {
		return nil, fmt.Errorf("EveNode Certificate, parse error")
	}

	deviceCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Errorf("EveNode Certificate,  x509 parse error")
		return nil, err
	}
	return deviceCert, nil
}

// compute hash and, fill-in the certificate structure and invoke publish
func prepareEvenNodeCertConfig(ctx *tpmMgrContext, algo evecommon.HashAlgorithm,
	cetType evecommon.ZCertType, origin types.ZCertOrigin, handle tpmutil.Handle,
	pubCert, pvtKey []byte) {
	hash, err := computeHash(pubCert, algo)
	if err != nil {
		errStr := fmt.Sprintf("prepareCertConfig failed: %v", err)
		log.Error(errStr)
		return
	}
	certInfo := types.ZCertConfig{
		HashAlgo:  algo,
		Type:      cetType,
		Origin:    origin,
		TpmHandle: handle,
		Hash:      hash,
		Cert:      pubCert,
		PvtKey:    pvtKey,
	}
	publishCerificate(ctx, certInfo)
}

// check for certificate of a given type in pubsub
func lookupEveNodeCertificate(ctx *tpmMgrContext, cetType evecommon.ZCertType,
	hash []byte) *types.ZCertConfig {
	pub := ctx.pubEveNodeCertConfig
	items := pub.GetAll()
	for _, item := range items {
		cert := item.(types.ZCertConfig)
		if cert.Type == cetType &&
			(len(hash) == 0 || bytes.Equal(hash, cert.Hash)) {
			return &cert
		}
	}
	return nil
}

// publish in pubsub
func publishCerificate(ctx *tpmMgrContext, config types.ZCertConfig) {
	key := config.Key()
	log.Debugf("publishCerificate %s", key)
	pub := ctx.pubEveNodeCertConfig
	pub.Publish(key, config)
	log.Debugf("publishCerificate %s Done", key)
}

// unpublish on pubsub
func unpublishCerificate(ctx *tpmMgrContext, key string) {
	log.Debugf("unpublishCerificate %s", key)
	pub := ctx.pubEveNodeCertConfig
	pub.Unpublish(key)
	log.Debugf("unpublishCerificate %s Done", key)
}
