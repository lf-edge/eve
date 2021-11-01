// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package tpmmgr

import (
	"crypto"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"reflect"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

type tpmMgrContext struct {
	subGlobalConfig    pubsub.Subscription
	subNodeAgentStatus pubsub.Subscription
	subAttestNonce     pubsub.Subscription
	pubAttestQuote     pubsub.Publication
	pubEdgeNodeCert    pubsub.Publication
	globalConfig       *types.ConfigItemValueMap
	GCInitialized      bool // GlobalConfig initialized
	DeviceReboot       bool //is the device rebooting?
}

const (
	agentName = "tpmmgr"

	maxPCRIndex = 23

	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

var (
	//location of the ecdh certificate
	ecdhCertFile = types.CertificateDirname + "/ecdh.cert.pem"

	//location of the attestation quote certificate
	quoteCertFile = types.CertificateDirname + "/attest.cert.pem"

	//EkCertFile is location of the endorsement key certificate
	EkCertFile = types.CertificateDirname + "/ek.cert.pem"

	//location of private key for the quote certificate
	//on devices without a TPM
	quoteKeyFile = types.CertificateDirname + "/attest.key.pem"

	pcrSelection     = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{7}}
	pcrListForQuote  = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}}
	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagNoDA | tpm2.FlagDecrypt |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
		},
	}
	//Default Ek Template as per
	//https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
	defaultEkTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{
			0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
			0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
			0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
			0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
			0x69, 0xAA,
		},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}
	//This is for ActivateCredentials() usage(Decrypt key)
	defaultSrkTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
			tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}
	//This is a restricted signing key, for vTPM guest usage
	defaultAkTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
			tpm2.FlagRestricted | tpm2.FlagSign | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}
	//This is a restricted signing key, for PCR Quote and other such uses
	defaultQuoteKeyTemplate = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
			tpm2.FlagRestricted | tpm2.FlagSign | tpm2.FlagNoDA,
		ECCParameters: &tpm2.ECCParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpm2.AlgSHA256,
			},
			CurveID: tpm2.CurveNISTP256,
		},
	}
	defaultEcdhKeyTemplate = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagNoDA | tpm2.FlagDecrypt |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
		},
	}
	debug         = false
	debugOverride bool // From command line arg
	logger        *logrus.Logger
	log           *base.LogObject
)

var toGoCurve = map[tpm2.EllipticCurve]elliptic.Curve{
	tpm2.CurveNISTP224: elliptic.P224(),
	tpm2.CurveNISTP256: elliptic.P256(),
	tpm2.CurveNISTP384: elliptic.P384(),
	tpm2.CurveNISTP521: elliptic.P521(),
}

//Helps creating various keys, according to the supplied template, and hierarchy
func createKey(keyHandle, ownerHandle tpmutil.Handle, template tpm2.Public, overwrite bool) error {
	rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
	if err != nil {
		log.Errorln(err)
		return err
	}
	defer rw.Close()
	if !overwrite {
		//don't overwrite if key already exists, and if the attributes match up
		pub, _, _, err := tpm2.ReadPublic(rw, keyHandle)
		if err == nil && pub.Attributes == template.Attributes {
			log.Noticef("Attributes match up, not re-creating 0x%X", keyHandle)
			return nil
		} else if err == nil {
			//key is present, but attributes not matching
			log.Noticef("Attribute mismatch, re-creating 0x%X", keyHandle)
		} else {
			//key is not present
			log.Noticef("key is not present, re-creating 0x%X", keyHandle)
		}
	}
	handle, _, err := tpm2.CreatePrimary(rw,
		tpm2.HandleOwner,
		pcrSelection,
		etpm.EmptyPassword,
		etpm.EmptyPassword,
		template)
	if err != nil {
		log.Errorf("create 0x%x failed: %s, do BIOS reset of TPM", keyHandle, err)
		return err
	}
	if err := tpm2.EvictControl(rw, etpm.EmptyPassword,
		tpm2.HandleOwner,
		keyHandle,
		keyHandle); err != nil {
		log.Tracef("EvictControl failed: %v", err)
	}
	if err := tpm2.EvictControl(rw, etpm.EmptyPassword,
		tpm2.HandleOwner, handle,
		keyHandle); err != nil {
		log.Errorf("EvictControl failed: %v, do BIOS reset of TPM", err)
		return err
	}
	return nil
}

func createDeviceKey() (crypto.PublicKey, error) {
	rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	defer rw.Close()

	tpmOwnerPasswd, err := etpm.ReadOwnerCrdl()
	if err != nil {
		return nil, fmt.Errorf("Reading owner credential failed: %s", err)
	}
	// No previous key, create new one
	// We later retrieve the public key from the handle to create the cert.
	signerHandle, newPubKey, err := tpm2.CreatePrimary(rw,
		tpm2.HandleOwner,
		pcrSelection,
		etpm.EmptyPassword,
		tpmOwnerPasswd,
		defaultKeyParams)

	if err != nil {
		log.Errorf("CreatePrimary failed: %s, do BIOS reset of TPM", err)
		return nil, err
	}
	if err := tpm2.EvictControl(rw, etpm.EmptyPassword,
		tpm2.HandleOwner,
		etpm.TpmDeviceKeyHdl,
		etpm.TpmDeviceKeyHdl); err != nil {
		log.Errorf("EvictControl failed: %v", err)
	}
	if err := tpm2.EvictControl(rw, etpm.EmptyPassword,
		tpm2.HandleOwner, signerHandle,
		etpm.TpmDeviceKeyHdl); err != nil {
		log.Errorf("EvictControl failed: %v, do BIOS reset of TPM", err)
		return nil, err
	}
	return newPubKey, nil
}

func writeDeviceCert() error {

	rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()

	if err := tpm2.NVUndefineSpace(rw, etpm.EmptyPassword,
		tpm2.HandleOwner, etpm.TpmDeviceCertHdl,
	); err != nil {
		log.Tracef("NVUndefineSpace failed: %v", err)
	}

	deviceCertBytes, err := ioutil.ReadFile(types.DeviceCertName)
	if err != nil {
		log.Errorf("Failed to read device cert file: %v", err)
		return err
	}

	// Define space in NV storage and clean up afterwards or subsequent runs will fail.
	if err := tpm2.NVDefineSpace(rw,
		tpm2.HandleOwner,
		etpm.TpmDeviceCertHdl,
		etpm.EmptyPassword,
		etpm.EmptyPassword,
		nil,
		tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead,
		uint16(len(deviceCertBytes)),
	); err != nil {
		log.Errorf("NVDefineSpace failed: %v", err)
		return err
	}

	// Write the data
	if err := tpm2.NVWrite(rw, tpm2.HandleOwner, etpm.TpmDeviceCertHdl,
		etpm.EmptyPassword, deviceCertBytes, 0); err != nil {
		log.Errorf("NVWrite %d bytes failed: %v",
			len(deviceCertBytes), err)
		return err
	}
	return nil
}

func readDeviceCert() error {

	rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()

	// Read all of the data with NVReadEx
	deviceCertBytes, err := tpm2.NVReadEx(rw, etpm.TpmDeviceCertHdl,
		tpm2.HandleOwner, etpm.EmptyPassword, 0)
	if err != nil {
		log.Errorf("NVReadEx failed: %v", err)
		return err
	}

	err = ioutil.WriteFile(types.DeviceCertName, deviceCertBytes, 0644)
	if err != nil {
		log.Errorf("Writing to device cert file failed: %v", err)
		return err
	}

	return nil
}

func genCredentials() error {
	//First try to read from TPM, if it was stored earlier
	err := readCredentials()
	if err != nil {
		id, err := uuid.NewV4()
		if err != nil {
			log.Errorf("NewV4 failed: %v", err)
			return err
		}
		//Write uuid to credentials file for faster access
		err = ioutil.WriteFile(etpm.TpmCredentialsFileName, []byte(id.String()), 0644)
		if err != nil {
			log.Errorf("Writing to credentials file failed: %v", err)
			return err
		}
		//Write credentials to TPM for permenant storage.
		err = writeCredentials()
		if err != nil {
			log.Errorf("Writing credentials to TPM failed: %v", err)
			return err
		}
	}
	return nil
}

func writeCredentials() error {

	rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()

	if err := tpm2.NVUndefineSpace(rw, etpm.EmptyPassword,
		tpm2.HandleOwner, etpm.TpmPasswdHdl,
	); err != nil {
		log.Tracef("NVUndefineSpace failed: %v", err)
	}

	tpmCredentialBytes, err := ioutil.ReadFile(etpm.TpmCredentialsFileName)
	if err != nil {
		log.Errorf("Failed to read credentials file: %v", err)
		return err
	}

	// Define space in NV storage and clean up afterwards or subsequent runs will fail.
	if err := tpm2.NVDefineSpace(rw,
		tpm2.HandleOwner,
		etpm.TpmPasswdHdl,
		etpm.EmptyPassword,
		etpm.EmptyPassword,
		nil,
		tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead,
		uint16(len(tpmCredentialBytes)),
	); err != nil {
		log.Errorf("NVDefineSpace failed: %v", err)
		return err
	}

	// Write the data
	if err := tpm2.NVWrite(rw, tpm2.HandleOwner, etpm.TpmPasswdHdl,
		etpm.EmptyPassword, tpmCredentialBytes, 0); err != nil {
		log.Errorf("NVWrite failed: %v", err)
		return err
	}
	return nil
}

func readCredentials() error {

	rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()

	// Read all of the data with NVReadEx
	tpmCredentialBytes, err := tpm2.NVReadEx(rw, etpm.TpmPasswdHdl,
		tpm2.HandleOwner, etpm.EmptyPassword, 0)
	if err != nil {
		log.Errorf("NVReadEx failed: %v", err)
		return err
	}

	err = ioutil.WriteFile(etpm.TpmCredentialsFileName, tpmCredentialBytes, 0644)
	if err != nil {
		log.Errorf("Writing to credentials file failed: %v", err)
		return err
	}

	return nil
}

func printCapability() {
	hwInfoStr, err := etpm.FetchTpmHwInfo()
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(hwInfoStr)
	}
}

func getQuote(nonce []byte) ([]byte, []byte, []types.PCRValue, error) {
	if !etpm.IsTpmEnabled() {
		//No TPM, not an error, return empty values
		return nil, nil, nil, nil
	}

	rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
	if err != nil {
		log.Errorf("Unable to open TPM device handle (%v), returning empty quote/PCRs", err)
		return nil, nil, nil, nil
	}
	defer rw.Close()
	pcrs := make([]types.PCRValue, 0)

	var i uint8
	for i = 0; i <= maxPCRIndex; i++ {
		pcrVal, err := tpm2.ReadPCR(rw, int(i), tpm2.AlgSHA256)
		if err != nil {
			log.Errorf("TPM ReadPCR cmd failed (%v), returning empty quote/PCRs", err)
			return nil, nil, nil, nil
		}

		pcr := types.PCRValue{
			Index:  i,
			Algo:   types.PCRExtendHashAlgoSha256,
			Digest: pcrVal,
		}
		pcrs = append(pcrs, pcr)
	}
	attestData, sig, err := tpm2.Quote(rw, etpm.TpmQuoteKeyHdl,
		etpm.EmptyPassword,
		etpm.EmptyPassword,
		nonce,
		pcrListForQuote,
		tpm2.AlgNull)
	if err != nil {
		log.Errorf("TPM Quote cmd failed (%v), returning empty quote/PCRs", err)
		return nil, nil, nil, nil
	} else {
		switch sig.Alg {
		case tpm2.AlgECDSA:
			signature, err := asn1.Marshal(struct {
				R, S *big.Int
			}{sig.ECC.R, sig.ECC.S})
			if err != nil {
				log.Errorf("Error in Marshaling AlgECDSA signature(%v), returning empty quote/PCRs", err)
				return nil, nil, nil, nil
			}
			return attestData, signature, pcrs, nil
		default:
			log.Errorf("Unsupported signature type %v, returning empty quote/PCRs", sig.Alg)
			return nil, nil, nil, nil
		}
	}
}

func printPCRs() {
	quote, signature, pcrs, err := getQuote([]byte("ThisIsRandomNonce"))
	if err != nil {
		fmt.Printf("Error in getting quote: %v", err)
	} else {
		fmt.Printf("attestData = %v\n", quote)
		for _, pcr := range pcrs {
			fmt.Printf("%d: %x\n", pcr.Index, pcr.Digest)
		}
		fmt.Printf("Quote: %x\n", quote)
		fmt.Printf("Signature: %x\n", signature)
	}
}

func testTpmEcdhSupport() error {
	rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
	if err != nil {
		log.Errorln(err)
		return err
	}
	defer rw.Close()

	z, p, err := tpm2.ECDHKeyGen(rw, etpm.TpmDeviceKeyHdl)
	if err != nil {
		fmt.Printf("generating Shared Secret failed: %s", err)
		return err
	}
	tpmOwnerPasswd, err := etpm.ReadOwnerCrdl()
	if err != nil {
		log.Errorf("Reading owner credential failed: %s", err)
		return err
	}

	z1, err := tpm2.ECDHZGen(rw, etpm.TpmDeviceKeyHdl, tpmOwnerPasswd, *p)
	if err != nil {
		fmt.Printf("recovering Shared Secret failed: %s", err)
		return err
	}
	fmt.Println(reflect.DeepEqual(z, z1))
	return nil
}

//Test ECDH key exchange and a symmetric cipher based on ECDH
func testEcdhAES() error {
	//Simulate Controller generating an ephemeral key
	privateA, publicAX, publicAY, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate A private/public key pair: %s\n", err)
	}

	//read public key from ecdh certificate
	certBytes, err := ioutil.ReadFile(ecdhCertFile)
	if err != nil {
		fmt.Printf("error in reading ecdh cert file: %v", err)
		return err
	}
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("error in parsing ecdh cert file: %v", err)
		return err
	}
	publicB := cert.PublicKey.(*ecdsa.PublicKey)

	//multiply privateA with publicB (Controller Part)
	X, Y := elliptic.P256().Params().ScalarMult(publicB.X, publicB.Y, privateA)

	fmt.Printf("publicAX, publicAY, X/Y = %v, %v, %v, %v\n", publicAX, publicAY, X, Y)
	encryptKey := etpm.Sha256FromECPoint(X, Y)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Printf("Unable to generate Initial Value %v\n", err)
	}

	msg := []byte("this is the secret")
	ciphertext := make([]byte, len(msg))
	etpm.AESEncrypt(ciphertext, msg, encryptKey[:], iv)

	recoveredMsg := make([]byte, len(ciphertext))
	certHash, err := getCertHash(certBytes, types.CertHashTypeSha256First16)
	if err != nil {
		fmt.Printf("getCertHash failed with error: %v", err)
		return err
	}

	isTpm := true
	if !etpm.IsTpmEnabled() || etpm.FileExists(etpm.EcdhKeyFile) {
		isTpm = false
	}

	ecdhCert := &types.EdgeNodeCert{
		HashAlgo: types.CertHashTypeSha256First16,
		CertID:   certHash,
		CertType: types.CertTypeEcdhXchange,
		Cert:     certBytes,
		IsTpm:    isTpm,
	}
	err = etpm.DecryptSecretWithEcdhKey(log, publicAX, publicAY, ecdhCert, iv, ciphertext, recoveredMsg)
	if err != nil {
		fmt.Printf("Decryption failed with error %v\n", err)
		return err
	}
	if reflect.DeepEqual(msg, recoveredMsg) == true {
		return nil
	} else {
		return fmt.Errorf("want %v, but got %v", msg, recoveredMsg)
	}
}

func testEncryptDecrypt() error {
	plaintext := []byte("This is the Secret Key")
	ciphertext, err := etpm.EncryptDecryptUsingTpm(plaintext, true)
	if err != nil {
		return err
	}
	decryptedtext, err := etpm.EncryptDecryptUsingTpm(ciphertext, false)
	if reflect.DeepEqual(plaintext, decryptedtext) == true {
		return nil
	} else {
		return fmt.Errorf("want %v, but got %v", plaintext, decryptedtext)
	}
}

func createQuoteCert() error {
	// certificate is already created
	if etpm.FileExists(quoteCertFile) {
		return nil
	}
	// try TPM
	if etpm.IsTpmEnabled() {
		if err := createQuoteCertOnTpm(); err == nil {
			return nil
		} else {
			// some issue with TPM. Fall back to soft cert
			log.Errorf("createQuoteCertOnTpm failed with err (%v), trying software certificate", err)
		}
	}
	// create soft certficate
	return createQuoteCertSoft()
}

func createEkCert() error {
	if etpm.FileExists(EkCertFile) {
		// certificate is already created
		return nil
	}
	if etpm.IsTpmEnabled() {
		return createEkCertOnTpm()
	}
	return nil
}

func createEkCertOnTpm() error {
	//Check if we already have the certificate
	if !etpm.FileExists(EkCertFile) {
		//Cert is not present, generate new one
		rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
		if err != nil {
			return err
		}
		defer rw.Close()

		deviceCertBytes, err := ioutil.ReadFile(types.DeviceCertName)
		if err != nil {
			return err
		}

		block, _ := pem.Decode(deviceCertBytes)
		if block == nil {
			return fmt.Errorf("Failed in PEM decoding of deviceCertBytes")
		}

		deviceCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		EKey, _, _, err := tpm2.ReadPublic(rw, etpm.TpmEKHdl)
		if err != nil {
			return err
		}

		publicKey, err := EKey.Key()
		if err != nil {
			return err
		}

		tpmPrivKey := etpm.TpmPrivateKey{}
		tpmPrivKey.PublicKey = tpmPrivKey.Public()
		template := createEkTemplate(*deviceCert)

		cert, err := x509.CreateCertificate(rand.Reader,
			&template, deviceCert, publicKey, tpmPrivKey)
		if err != nil {
			return err
		}

		certBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		}

		certBytes := pem.EncodeToMemory(certBlock)
		if certBytes == nil {
			return fmt.Errorf("empty bytes after encoding to PEM")
		}

		err = ioutil.WriteFile(EkCertFile, certBytes, 0644)
		if err != nil {
			return err
		}

	}
	return nil
}

// create deviceCert Template with 20 year lifetime
// If we have a /config/soft_serial we put it in the CN
func createDeviceCertTemplate() *x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	// Backdate one day in case clock is off a bit
	yesterday := time.Now().AddDate(0, 0, -1)

	// We'd like to put hardware.GetSoftSerial(log) and
	// hardware.GetProductSerial(log) in the CN, but the size seems to
	// be limited to 768 bytes on some devices so we refrain from that.
	cn := "EVE"
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"The Linux Foundation"},
			CommonName:   cn,
		},
		NotBefore: yesterday,
		NotAfter:  yesterday.AddDate(20, 0, 0),
		IsCA:      true,
		// No x509.KeyUsageKeyEncipherment for ECC
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	return &template
}

// generate the TPM device key and certificate,
// the certificate is self-signed using the device private key
func createDeviceCertOnTpm(pubkey crypto.PublicKey) error {
	//Check if we already have the certificate
	if etpm.FileExists(types.DeviceCertName) {
		return nil
	}

	//Cert is not present, generate new one
	rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()

	deviceKey, _, _, err := tpm2.ReadPublic(rw, etpm.TpmDeviceKeyHdl)
	if err != nil {
		return err
	}

	publicKey, err := deviceKey.Key()
	if err != nil {
		return err
	}

	// Need to force the public key since we haven't created
	// the device cert yet.
	etpm.SetDevicePublicKey(pubkey)
	tpmPrivKey := etpm.TpmPrivateKey{}
	tpmPrivKey.PublicKey = tpmPrivKey.Public()

	template := createDeviceCertTemplate()
	// create a self-signed certificate. template = parent
	var parent = template

	cert, err := x509.CreateCertificate(rand.Reader,
		template, parent, publicKey, tpmPrivKey)
	if err != nil {
		return fmt.Errorf("Failed to create device certificate: %w",
			err)
	}

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}

	certBytes := pem.EncodeToMemory(certBlock)
	if certBytes == nil {
		return fmt.Errorf("empty bytes after encoding to PEM")
	}

	err = ioutil.WriteFile(types.DeviceCertName, certBytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

// generate the software device key and certificate,
// the certificate is self-signed using the device private key
// Assumes no TPM hence device private key is in a file
func createDeviceCertSoft() error {
	// Generate private key
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("Failed to generate software device key pair: %v",
			err)
	}

	// get the device cert template
	template := createDeviceCertTemplate()
	// create a self-signed certificate. template = parent
	var parent = template

	derBytes, err := x509.CreateCertificate(rand.Reader,
		template, parent, certPrivKey.Public(), certPrivKey)
	if err != nil {
		return fmt.Errorf("Failed to create device certificate: %w",
			err)
	}

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	// public cert bytes
	certBytes := pem.EncodeToMemory(certBlock)
	if certBytes == nil {
		return fmt.Errorf("Failed in PEM encoding of device cert: empty bytes")
	}

	// private cert bytes
	privBytes, err := x509.MarshalECPrivateKey(certPrivKey)
	if err != nil {
		return fmt.Errorf("Failed in MarshalECPrivateKey of ECDH cert: %v", err)
	}
	keyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}

	keyBytes := pem.EncodeToMemory(keyBlock)
	if keyBytes == nil {
		return fmt.Errorf("Failed in PEM encoding of ECDH key: empty bytes")
	}
	return writeDeviceCertToFile(certBytes, keyBytes)
}

func writeDeviceCertToFile(certBytes, keyBytes []byte) error {
	if err := ioutil.WriteFile(types.DeviceKeyName, keyBytes, 0644); err != nil {
		return err
	}
	return ioutil.WriteFile(types.DeviceCertName, certBytes, 0644)
}

func createOtherKeys(override bool) error {
	if err := createKey(etpm.TpmEKHdl, tpm2.HandleEndorsement, defaultEkTemplate, override); err != nil {
		return fmt.Errorf("Error in creating Endorsement key: %w ", err)
	}
	if err := createKey(etpm.TpmSRKHdl, tpm2.HandleOwner, defaultSrkTemplate, override); err != nil {
		return fmt.Errorf("Error in creating SRK key: %w ", err)
	}
	if err := createKey(etpm.TpmAKHdl, tpm2.HandleOwner, defaultAkTemplate, override); err != nil {
		return fmt.Errorf("Error in creating Attestation key: %w ", err)
	}
	if err := createKey(etpm.TpmQuoteKeyHdl, tpm2.HandleOwner, defaultQuoteKeyTemplate, override); err != nil {
		return fmt.Errorf("Error in creating Quote key: %w ", err)
	}
	if err := createKey(etpm.TpmEcdhKeyHdl, tpm2.HandleOwner, defaultEcdhKeyTemplate, override); err != nil {
		return fmt.Errorf("Error in creating ECDH key: %w ", err)
	}
	return nil
}

// create Ek Template using the deviceCert for lifetimes
// Use a CommonName to differentiate from the device cert itself
func createEkTemplate(deviceCert x509.Certificate) x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"San Francisco"},
			Organization: []string{"The Linux Foundation"},
			CommonName:   "Device Endorsement Key certificate",
		},
		NotBefore: deviceCert.NotBefore,
		NotAfter:  deviceCert.NotAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	return template
}

func createQuoteCertOnTpm() error {
	//Check if we already have the certificate
	if !etpm.FileExists(quoteCertFile) {
		//Cert is not present, generate new one
		rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
		if err != nil {
			return err
		}
		defer rw.Close()

		deviceCertBytes, err := ioutil.ReadFile(types.DeviceCertName)
		if err != nil {
			return err
		}

		block, _ := pem.Decode(deviceCertBytes)
		if block == nil {
			return fmt.Errorf("Failed in PEM decoding of deviceCertBytes")
		}

		deviceCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		quoteKey, _, _, err := tpm2.ReadPublic(rw, etpm.TpmQuoteKeyHdl)
		if err != nil {
			return err
		}

		publicKey, err := quoteKey.Key()
		if err != nil {
			return err
		}

		tpmPrivKey := etpm.TpmPrivateKey{}
		tpmPrivKey.PublicKey = tpmPrivKey.Public()
		template := createQuoteTemplate(*deviceCert)

		cert, err := x509.CreateCertificate(rand.Reader,
			&template, deviceCert, publicKey, tpmPrivKey)
		if err != nil {
			return err
		}

		certBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		}

		certBytes := pem.EncodeToMemory(certBlock)
		if certBytes == nil {
			return fmt.Errorf("empty bytes after encoding to PEM")
		}

		err = ioutil.WriteFile(quoteCertFile, certBytes, 0644)
		if err != nil {
			return err
		}

	}
	return nil
}

// create Quote Template using the deviceCert for lifetimes
// Use a CommonName to differentiate from the device cert itself
func createQuoteTemplate(deviceCert x509.Certificate) x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"San Francisco"},
			Organization: []string{"The Linux Foundation"},
			CommonName:   "Device Attestation certificate",
		},
		NotBefore: deviceCert.NotBefore,
		NotAfter:  deviceCert.NotAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	return template
}

// generate the software Quote key and certificate,
// the certificate is signed using the device private key
// Assumes no TPM hence device private key is in a file
func createQuoteCertSoft() error {
	// get the device software private key
	devicePrivKey, err := etpm.GetDevicePrivateKey()
	if err != nil {
		return fmt.Errorf("Failed reading device key with error: %v", err)
	}

	// generate the quote private key
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("Failed to generate software ECDSA key pair: %v", err)
	}

	deviceCertBytes, err := ioutil.ReadFile(types.DeviceCertName)
	if err != nil {
		return fmt.Errorf("Failed to read device cert file: %v", err)
	}

	block, _ := pem.Decode(deviceCertBytes)
	if block == nil {
		return fmt.Errorf("Failed in PEM decoding of deviceCertBytes")
	}

	deviceCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("Failed to parse device cert bytes with error: %v", err)
	}

	// get the quote template
	template := createQuoteTemplate(*deviceCert)

	// create the certificate and sign with device private key
	derBytes, err := x509.CreateCertificate(rand.Reader,
		&template, deviceCert, certPrivKey.Public(), devicePrivKey)
	if err != nil {
		return fmt.Errorf("Failed to create Quote certificate: %v", err)
	}

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	// public cert bytes
	certBytes := pem.EncodeToMemory(certBlock)
	if certBytes == nil {
		return fmt.Errorf("Failed in PEM encoding of Quote cert: empty bytes")
	}

	// private cert bytes
	privBytes, err := x509.MarshalECPrivateKey(certPrivKey)
	if err != nil {
		return fmt.Errorf("Failed in MarshalECPrivateKey of Quote cert: %v", err)
	}
	keyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}

	keyBytes := pem.EncodeToMemory(keyBlock)
	if keyBytes == nil {
		return fmt.Errorf("Failed in PEM encoding of Quote key: empty bytes")
	}
	return writeQuoteCertToFile(certBytes, keyBytes)
}

func writeQuoteCertToFile(certBytes, keyBytes []byte) error {
	if err := ioutil.WriteFile(quoteKeyFile, keyBytes, 0644); err != nil {
		return err
	}
	if err := ioutil.WriteFile(quoteCertFile, certBytes, 0644); err != nil {
		return err
	}
	return nil
}

func getQuoteCert(certPath string) ([]byte, error) {
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read Quote certificate: %v", err)
	}
	return certBytes, nil
}

func createEcdhCert() error {
	// certificate is already created
	if etpm.FileExists(ecdhCertFile) {
		return nil
	}
	// try TPM
	if etpm.IsTpmEnabled() {
		if err := createEcdhCertOnTpm(); err == nil {
			return nil
		} else {
			// some issue with TPM. Fall back to soft cert
			log.Errorf("createEcdhCertOnTpm failed with err (%v), trying software certificate", err)
		}
	}
	// create soft certficate
	return createEcdhCertSoft()
}

func createEcdhCertOnTpm() error {
	//Check if we already have the certificate
	if !etpm.FileExists(ecdhCertFile) {
		//Cert is not present, generate new one
		rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
		if err != nil {
			return err
		}
		defer rw.Close()

		deviceCertBytes, err := ioutil.ReadFile(types.DeviceCertName)
		if err != nil {
			return err
		}

		block, _ := pem.Decode(deviceCertBytes)
		if block == nil {
			return fmt.Errorf("Failed in PEM decoding of deviceCertBytes")
		}

		deviceCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		ecdhKey, _, _, err := tpm2.ReadPublic(rw, etpm.TpmEcdhKeyHdl)
		if err != nil {
			return err
		}

		publicKey, err := ecdhKey.Key()
		if err != nil {
			return err
		}

		tpmPrivKey := etpm.TpmPrivateKey{}
		tpmPrivKey.PublicKey = tpmPrivKey.Public()
		template := createEcdhTemplate(*deviceCert)

		cert, err := x509.CreateCertificate(rand.Reader,
			&template, deviceCert, publicKey, tpmPrivKey)
		if err != nil {
			return err
		}

		certBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		}

		certBytes := pem.EncodeToMemory(certBlock)
		if certBytes == nil {
			return fmt.Errorf("empty bytes after encoding to PEM")
		}

		err = ioutil.WriteFile(ecdhCertFile, certBytes, 0644)
		if err != nil {
			return err
		}

	}
	return nil
}

// create Ecdh Template using the deviceCert for lifetimes
// Use a CommonName to differentiate from the device cert itself
func createEcdhTemplate(deviceCert x509.Certificate) x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"San Francisco"},
			Organization: []string{"The Linux Foundation"},
			CommonName:   "Device ECDH certificate",
		},
		NotBefore: deviceCert.NotBefore,
		NotAfter:  deviceCert.NotAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	return template
}

// generate the software ECDH key and certificate,
// the certificate is signed using the device private key
// Assumes no TPM hence device private key is in a file
func createEcdhCertSoft() error {
	// get the device software private key
	devicePrivKey, err := etpm.GetDevicePrivateKey()
	if err != nil {
		return fmt.Errorf("Failed reading device key with error: %v", err)
	}

	// generate the ecdh private key
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("Failed to generate software ECDSA key pair: %v", err)
	}

	deviceCertBytes, err := ioutil.ReadFile(types.DeviceCertName)
	if err != nil {
		return fmt.Errorf("Failed to read device cert file: %v", err)
	}

	block, _ := pem.Decode(deviceCertBytes)
	if block == nil {
		return fmt.Errorf("Failed in PEM decoding of deviceCertBytes")
	}

	deviceCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	// get the ecdh template
	template := createEcdhTemplate(*deviceCert)

	// create the certificate and sign with device private key
	derBytes, err := x509.CreateCertificate(rand.Reader,
		&template, deviceCert, certPrivKey.Public(), devicePrivKey)
	if err != nil {
		return fmt.Errorf("Failed to create ECDH certificate: %v", err)
	}

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	// public cert bytes
	certBytes := pem.EncodeToMemory(certBlock)
	if certBytes == nil {
		return fmt.Errorf("Failed in PEM encoding of ECDH cert: empty bytes")
	}

	// private cert bytes
	privBytes, err := x509.MarshalECPrivateKey(certPrivKey)
	if err != nil {
		return fmt.Errorf("Failed in MarshalECPrivateKey of ECDH cert: %v", err)
	}
	keyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}

	keyBytes := pem.EncodeToMemory(keyBlock)
	if keyBytes == nil {
		return fmt.Errorf("Failed in PEM encoding of ECDH key: empty bytes")
	}
	return writeEcdhCertToFile(certBytes, keyBytes)
}

func writeEcdhCertToFile(certBytes, keyBytes []byte) error {
	if err := ioutil.WriteFile(etpm.EcdhKeyFile, keyBytes, 0644); err != nil {
		return err
	}
	return ioutil.WriteFile(ecdhCertFile, certBytes, 0644)
}

func publishEdgeNodeCert(ctx *tpmMgrContext, config types.EdgeNodeCert) {
	key := config.Key()
	log.Tracef("publishEdgeNodeCert %s", key)
	pub := ctx.pubEdgeNodeCert
	pub.Publish(key, config)
	log.Tracef("publishEdgeNodeCert %s Done", key)
}

func readEdgeNodeCert(certPath string) ([]byte, error) {
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("readEdgeNodeCert failed with error: %v", err)
	}
	return certBytes, nil
}

func getCertHash(cert []byte, hashAlgo types.CertHashType) ([]byte, error) {
	certHash := sha256.Sum256(cert)
	switch hashAlgo {
	case types.CertHashTypeSha256First16:
		return certHash[:16], nil
	default:
		return []byte{}, fmt.Errorf("Unsupported cert hash type: %d\n", hashAlgo)
	}
}

func publishEdgeNodeCertToController(ctx *tpmMgrContext, certFile string, certType types.CertType, isTpm bool, metaDataItems []types.CertMetaData) {
	log.Functionf("publishEdgeNodeCertToController started")
	if !etpm.FileExists(certFile) {
		log.Errorf("publishEdgeNodeCertToController failed: no cert file")
		return
	}
	certBytes, err := readEdgeNodeCert(certFile)
	if err != nil {
		errStr := fmt.Sprintf("publishEdgeNodeCertToController failed: %v", err)
		log.Error(errStr)
		return
	}
	certHash, err := getCertHash(certBytes, types.CertHashTypeSha256First16)
	if err != nil {
		errStr := fmt.Sprintf("publishEdgeNodeCertToController failed: %v", err)
		log.Error(errStr)
		return
	}
	cert := types.EdgeNodeCert{
		HashAlgo: types.CertHashTypeSha256First16,
		CertID:   certHash,
		CertType: certType,
		Cert:     certBytes,
		IsTpm:    isTpm,
	}
	if len(metaDataItems) > 0 {
		cert.MetaDataItems = make([]types.CertMetaData, len(metaDataItems))
		for i, metaData := range metaDataItems {
			cert.MetaDataItems[i].Type = metaData.Type
			cert.MetaDataItems[i].Data = metaData.Data
		}
	}
	publishEdgeNodeCert(ctx, cert)
	log.Functionf("publishEdgeNodeCertToController Done")
}

func getEkCertMetaData() ([]types.CertMetaData, error) {
	rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
	if err != nil {
		return nil, fmt.Errorf("Unable to open TPM device: %v", err)
	}
	defer rw.Close()

	pub, _, _, err := tpm2.ReadPublic(rw, etpm.TpmEKHdl)
	if err != nil {
		return nil, err
	}
	pubWireFormat, err := pub.Encode()
	if err != nil {
		return nil, err
	}
	//Wrap TPM2_PUBLIC in TPM2B_PUBLIC
	packedPubKey, err := tpmutil.Pack(tpmutil.U16Bytes(pubWireFormat))
	if err != nil {
		return nil, err
	}
	//pubBase64 := base64.StdEncoding.EncodeToString(pubWireFormat)
	EkCertMetaData := make([]types.CertMetaData, 1)
	EkCertMetaData[0].Type = types.CertMetaDataTypeTpm2Public
	//EkCertMetaData[0].Data = []byte(pubBase64)
	EkCertMetaData[0].Data = packedPubKey
	return EkCertMetaData, nil
}

// Write TPM vendor, firmware info to given file.
func saveTpmInfo(filename string) error {
	info, err := etpm.FetchTpmHwInfo()
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, []byte(info), 0600)
}

//Create required directories, if not already created
func initializeDirs() {
	if _, err := os.Stat(types.CertificateDirname); err != nil {
		log.Tracef("Create %s", types.CertificateDirname)
		if err := os.MkdirAll(types.CertificateDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
}

// Run is the entry point for tpmmgr, from zedbox
//nolint:funlen,gocognit,gocyclo
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject) int {
	logger = loggerArg
	log = logArg
	var err error
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		logger.SetLevel(logrus.TraceLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	if len(flag.Args()) == 0 {
		log.Error("Insufficient arguments")
		return 1
	}

	switch flag.Args()[0] {
	case "createDeviceCert":
		//Create required directories if not present
		initializeDirs()
		if err = genCredentials(); err != nil {
			//No need for Fatal, caller will take action based on return code.
			log.Errorf("Error in generating credentials: %v", err)
			return 1
		}
		// Do we already have a device cert in the TPM NVRAW?
		// If so write to /config/device.cert.pem
		if err = readDeviceCert(); err == nil {
			log.Noticef("readDeviceCert success, re-using key and cert")
			return 0

		}
		log.Errorf("readDeviceCert failed %s, generating new key and cert",
			err)
		pubkey, err := createDeviceKey()
		if err != nil {
			//No need for Fatal, caller will take action based on return code.
			log.Errorf("Error in creating device primary key: %v ", err)
			return 1
		}
		if err := createDeviceCertOnTpm(pubkey); err != nil {
			log.Errorf("Failed to create TPM device cert: %v", err)
			return 1
		}
		// Write to /config/device.cert.pem and backup to TPM NVRAW
		if err = writeDeviceCert(); err != nil {
			//No need for Fatal, caller will take action based on return code.
			log.Errorf("Failed to backup device cert in TPM NVRAM: %v",
				err)
			return 1
		}
		if err := createOtherKeys(true); err != nil {
			//No need for Fatal, caller will take action based on return code.
			log.Errorf("Error in creating other keys: %v ", err)
			return 1
		}

	case "createSoftDeviceCert":
		//Create required directories if not present
		initializeDirs()
		if err := createDeviceCertSoft(); err != nil {
			log.Errorf("Failed to create soft device cert: %v", err)
			return 1
		}

	case "readCredentials":
		if err = readCredentials(); err != nil {
			//No need for Fatal, caller will take action based on return code.
			log.Errorf("Error in reading credentials: %v", err)
			return 1
		}

	case "genCredentials":
		if err = genCredentials(); err != nil {
			//No need for Fatal, caller will take action based on return code.
			log.Errorf("Error in generating credentials: %v", err)
			return 1
		}
	case "saveTpmInfo":
		//nolint:gomnd // very straightforward for anyone to understand why "2" is used here
		if len(flag.Args()) != 2 {
			log.Error("Insufficient arguments. Usage: tpmmgr saveTpmInfo filePath")

			return 1
		}

		if err := saveTpmInfo(flag.Args()[1]); err != nil {
			log.Errorf("saveTpmInfo failed: %v", err)
		}
	case "runAsService":
		log.Functionf("Starting %s", agentName)

		//Create required directories if not present
		initializeDirs()

		if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
			log.Fatal(err)
		}

		// Run a periodic timer so we always update StillRunning
		stillRunning := time.NewTicker(15 * time.Second)
		ps.StillRunning(agentName, warningTime, errorTime)

		// Context to pass around
		ctx := tpmMgrContext{}

		// Look for global config such as log levels
		subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
			AgentName:     "zedagent",
			MyAgentName:   agentName,
			TopicImpl:     types.ConfigItemValueMap{},
			Persistent:    true,
			Activate:      false,
			Ctx:           &ctx,
			CreateHandler: handleGlobalConfigCreate,
			ModifyHandler: handleGlobalConfigModify,
			DeleteHandler: handleGlobalConfigDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
		if err != nil {
			log.Fatal(err)
		}
		ctx.subGlobalConfig = subGlobalConfig
		subGlobalConfig.Activate()

		subNodeAgentStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
			AgentName:     "nodeagent",
			MyAgentName:   agentName,
			TopicImpl:     types.NodeAgentStatus{},
			Activate:      false,
			Ctx:           &ctx,
			CreateHandler: handleNodeAgentStatusCreate,
			ModifyHandler: handleNodeAgentStatusModify,
			DeleteHandler: handleNodeAgentStatusDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
		if err != nil {
			log.Fatal(err)
		}
		ctx.subNodeAgentStatus = subNodeAgentStatus
		subNodeAgentStatus.Activate()

		pubAttestQuote, err := ps.NewPublication(
			pubsub.PublicationOptions{
				AgentName: agentName,
				TopicType: types.AttestQuote{},
			})
		if err != nil {
			log.Fatal(err)
		}
		ctx.pubAttestQuote = pubAttestQuote
		subAttestNonce, err := ps.NewSubscription(pubsub.SubscriptionOptions{
			AgentName:     "zedagent",
			MyAgentName:   agentName,
			TopicImpl:     types.AttestNonce{},
			Activate:      false,
			Ctx:           &ctx,
			CreateHandler: handleAttestNonceCreate,
			ModifyHandler: handleAttestNonceModify,
			DeleteHandler: handleAttestNonceDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
		if err != nil {
			log.Fatal(err)
		}
		ctx.subAttestNonce = subAttestNonce
		subAttestNonce.Activate()

		pubEdgeNodeCert, err := ps.NewPublication(
			pubsub.PublicationOptions{
				AgentName:  agentName,
				Persistent: true,
				TopicType:  types.EdgeNodeCert{},
			})
		if err != nil {
			log.Fatal(err)
		}
		ctx.pubEdgeNodeCert = pubEdgeNodeCert

		//publish ECDH cert
		publishEdgeNodeCertToController(&ctx, ecdhCertFile, types.CertTypeEcdhXchange,
			etpm.IsTpmEnabled() && !etpm.FileExists(etpm.EcdhKeyFile), nil)

		//publish attestation quote cert
		publishEdgeNodeCertToController(&ctx, quoteCertFile, types.CertTypeRestrictSigning,
			etpm.IsTpmEnabled() && !etpm.FileExists(quoteKeyFile), nil)

		ekCertMetaData, err := getEkCertMetaData()
		if err == nil {
			publishEdgeNodeCertToController(&ctx, EkCertFile, types.CertTypeEk, true,
				ekCertMetaData)
		} else {
			log.Errorf("ekCertMetaData failed: %v", err)
		}

		// Pick up debug aka log level before we start real work
		for !ctx.GCInitialized {
			log.Functionf("waiting for GCInitialized")
			select {
			case change := <-subGlobalConfig.MsgChan():
				subGlobalConfig.ProcessChange(change)
			case change := <-ctx.subNodeAgentStatus.MsgChan():
				ctx.subNodeAgentStatus.ProcessChange(change)
			case <-stillRunning.C:
			}
			ps.StillRunning(agentName, warningTime, errorTime)
		}
		log.Functionf("processed GlobalConfig")

		if etpm.IsTpmEnabled() && !etpm.FileExists(etpm.TpmCredentialsFileName) {
			err := readCredentials()
			if err != nil {
				//this indicates that we are in a very bad state
				log.Errorf("TPM is enabled, but credential file is absent: %v", err)
				return 1
			}
		}
		for {
			select {
			case change := <-subGlobalConfig.MsgChan():
				subGlobalConfig.ProcessChange(change)
			case change := <-ctx.subNodeAgentStatus.MsgChan():
				ctx.subNodeAgentStatus.ProcessChange(change)
			case change := <-ctx.subAttestNonce.MsgChan():
				ctx.subAttestNonce.ProcessChange(change)
			case <-stillRunning.C:
				ps.StillRunning(agentName, warningTime, errorTime)
			}
		}
	case "printCapability":
		printCapability()
	case "printPCRs":
		printPCRs()
	case "testTpmEcdhSupport":
		testTpmEcdhSupport()
	case "testEcdhAES":
		if err = testEcdhAES(); err != nil {
			fmt.Printf("failed with error %v", err)
		} else {
			fmt.Printf("test passed")
		}
	case "testEncryptDecrypt":
		if err = testEncryptDecrypt(); err != nil {
			fmt.Printf("failed with error %v", err)
		} else {
			fmt.Printf("test passed")
		}
	case "createCerts":
		//Create required directories if not present
		initializeDirs()

		// Create additional security keys if already not created,
		// followed by security certificates
		if err = createOtherKeys(false); err != nil {
			log.Errorf("Error in creating other keys: %v ", err)
			return 1
		}
		fallthrough
	case "createSoftCerts":
		if err := createEcdhCert(); err != nil {
			log.Errorf("Error in creating Ecdh Certificate: %v", err)
			return 1
		}
		if err := createQuoteCert(); err != nil {
			log.Errorf("Error in creating Quote Certificate: %v", err)
			return 1
		}
		if err := createEkCert(); err != nil {
			log.Errorf("Error in creating Endorsement Key Certificate: %v", err)
			return 1
		}
	default:
		//No need for Fatal, caller will take action based on return code.
		log.Errorf("Unknown argument %s", flag.Args()[0])
		return 1
	}
	return 0
}

func handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*tpmMgrContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride, logger)
	if gcp != nil {
		ctx.GCInitialized = true
	}
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*tpmMgrContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride, logger)
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}

func handleNodeAgentStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleNodeAgentStatusImpl(ctxArg, key, statusArg)
}

func handleNodeAgentStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleNodeAgentStatusImpl(ctxArg, key, statusArg)
}

func handleNodeAgentStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.NodeAgentStatus)
	ctx := ctxArg.(*tpmMgrContext)
	if key != "nodeagent" {
		log.Functionf("handleNodeAgentStatusImpl: ignoring %s", key)
		return
	}
	ctx.DeviceReboot = status.DeviceReboot
	log.Functionf("handleNodeAgentStatusImpl done for %s: %v", key, ctx.DeviceReboot)
}

func handleNodeAgentStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleNodeAgentStatusDelete for %s", key)
	ctx := ctxArg.(*tpmMgrContext)

	if key != "nodeagent" {
		log.Functionf("handleNodeAgentStatusDelete: ignoring %s", key)
		return
	}
	ctx.DeviceReboot = false
	log.Functionf("handleNodeAgentStatusDelete done for %s: %v", key, ctx.DeviceReboot)
}

func readNodeAgentStatus(ctx *tpmMgrContext) (bool, error) {
	nodeAgentStatus, err := ctx.subNodeAgentStatus.Get("nodeagent")
	if err != nil {
		return false, err
	}
	status := nodeAgentStatus.(types.NodeAgentStatus)
	return status.DeviceReboot, nil
}

func handleAttestNonceCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleAttestNonceImpl(ctxArg, key, statusArg)
}

func handleAttestNonceModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleAttestNonceImpl(ctxArg, key, statusArg)
}

func handleAttestNonceImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleAttestNonceImpl received")
	ctx := ctxArg.(*tpmMgrContext)
	nonceReq := statusArg.(types.AttestNonce)
	log.Functionf("Received quote request from %s", nonceReq.Requester)
	quote, signature, pcrs, err := getQuote(nonceReq.Nonce)
	if err != nil {
		log.Errorf("Error in fetching quote %v", err)
	}
	attestQuote := types.AttestQuote{
		Nonce:     nonceReq.Nonce,
		SigType:   types.EcdsaSha256,
		Signature: signature,
		Quote:     quote,
		PCRs:      pcrs,
	}
	pubKey := attestQuote.Key()
	log.Tracef("publishing quote for nonce %x", pubKey)
	pub := ctx.pubAttestQuote
	pub.Publish(pubKey, attestQuote)
	log.Tracef("handleAttestNonceImpl done")
}

func handleAttestNonceDelete(ctxArg interface{}, key string, statusArg interface{}) {
	log.Functionf("handleAttestNonceDelete received")
	ctx := ctxArg.(*tpmMgrContext)
	pub := ctx.pubAttestQuote
	st, _ := pub.Get(key)
	if st != nil {
		log.Functionf("Unpublishing quote for nonce %x", key)
		pub := ctx.pubAttestQuote
		pub.Unpublish(key)
	}
	log.Functionf("handleAttestNonceDelete done")
}
