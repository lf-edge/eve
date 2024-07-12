// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/api/go/attest"
	"github.com/schollz/progressbar/v3"
	"google.golang.org/protobuf/proto"
)

const (
	// TPM related constants
	tpmDevicePath          = "/dev/tpmrm0"
	tpmCredentialsFileName = "/config/tpm_credential"
	deviceCertName         = "/config/device.cert.pem"

	// TPM key handles
	tpmEKHdl             tpmutil.Handle = 0x81000001
	tpmSRKHdl            tpmutil.Handle = 0x81000002
	tpmAKHdl             tpmutil.Handle = 0x81000003
	tpmQuoteKeyHdl       tpmutil.Handle = 0x81000004
	tpmEcdhKeyHdl        tpmutil.Handle = 0x81000005
	tpmDeviceKeyHdl      tpmutil.Handle = 0x817FFFFF
	tpmSealedDiskPrivHdl tpmutil.Handle = 0x1800000
	tpmSealedDiskPubHdl  tpmutil.Handle = 0x1900000

	// TPM properties
	tpmPropertyManufacturer tpm2.TPMProp = 0x105
	tpmPropertyVendorStr1   tpm2.TPMProp = 0x106
	tpmPropertyVendorStr2   tpm2.TPMProp = 0x107
	tpmPropertyFirmVer1     tpm2.TPMProp = 0x10b
	tpmPropertyFirmVer2     tpm2.TPMProp = 0x10c

	// TPM key generation types
	genDevKey = 0
	genEKKey  = 1
	genSRKKey = 2
	genAKKey  = 3
	genQuote  = 4
	genECDH   = 5

	// Max password length
	tpmMaxPasswdLength = 7
)

var (
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

	pcrSelection = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7}}
	logFilePath  string
)

var vendorRegistry = map[uint32]string{
	0x414D4400: "AMD",
	0x41544D4C: "Atmel",
	0x4252434D: "Broadcom",
	0x48504500: "HPE",
	0x49424d00: "IBM",
	0x49465800: "Infineon",
	0x494E5443: "Intel",
	0x4C454E00: "Lenovo",
	0x4D534654: "Microsoft",
	0x4E534D20: "National SC",
	0x4E545A00: "Nationz",
	0x4E544300: "Nuvoton",
	0x51434F4D: "Qualcomm",
	0x534D5343: "SMSC",
	0x53544D20: "ST Microelectronics",
	0x534D534E: "Samsung",
	0x534E5300: "Sinosun",
	0x54584E00: "Texas Instruments",
	0x57454300: "Winbond",
	0x524F4343: "Fuzhou Rockchip",
	0x474F4F47: "Google",
}

var (
	tpmPath       = flag.String("tpm-path", tpmDevicePath, "Path to the TPM device (character device)")
	tpmPass       = flag.String("tpm-pass", "", "TPM password (if needed)")
	vpubIndex     = flag.Uint("vpub-index", uint(tpmSealedDiskPubHdl), "Vault key public part nv-index")
	vprivIndex    = flag.Uint("vpriv-index", uint(tpmSealedDiskPrivHdl), "Vault Key private part nv-index")
	srkIndex      = flag.Uint("srk-index", uint(tpmSRKHdl), "Storage Root Key (SRK) nv-index")
	ecdhIndex     = flag.Uint("ecdh-index", uint(tpmEcdhKeyHdl), "ECC key (aka ECDH key) nv-index")
	devKeyIndex   = flag.Uint("devkey-index", uint(tpmDeviceKeyHdl), "Device key nv-index")
	devCertPath   = flag.String("devkey-cert-path", deviceCertName, "Path to the device cert file")
	tpmCredPath   = flag.String("tpm-cred", tpmCredentialsFileName, "Path to the TPM credential file")
	pcrHash       = flag.String("pcr-hash", "sha1", "PCR Hash algorithm (sha1, sha256)")
	pcrIndexes    = flag.String("pcr-index", "0", "PCR Indexes to use for sealing and unsealing")
	exportEnc     = flag.Bool("export-vkey", false, "Export enctypted vault key")
	output        = flag.String("output", "", "Output file")
	input         = flag.String("input", "", "Input file")
	checkCert     = flag.Bool("check-dev-cert", false, "Compare the device cert from disk with the device cert inside TPM")
	sealKey       = flag.Bool("seal-key", false, "Seal the key in TPM")
	tpmInfo       = flag.Bool("info", false, "Print TPM information")
	clrTpm        = flag.Bool("clear", false, "Clear the TPM")
	arbitKeyIndex = flag.Uint("key-index", 0, "Arbitrary key nv-index, used in conjunction with gen-key and remove-key")
	removeKey     = flag.Bool("remove-key", false, "Remove key from TPM by nv-index")
	testCount     = flag.Int("test-count", 1, "Number of times to run the test, used with test")
	showBar       = flag.Bool("show-bar", false, "Show progress bar for tests")
	testRegen     = flag.Bool("test-key-regen", false, "Regenerate the keys on every iteration of the secleted test")
	logFile       = flag.String("log", "", "log file path")
	genKey        = flag.Int("gen-key", -1, "Generate key in TPM :\n"+
		"\t0: Device key\n"+
		"\t1: EK key\n"+
		"\t2: SRK key\n"+
		"\t3: Attestation key\n"+
		"\t4: Quote key\n"+
		"\t5: ECDH key\n\t")
	testTpm = flag.Int("test", -1, "Test TPM operations:\n"+
		"\t0: Test ECDH with default device key and ECC key\n"+
		"\t1: Generated a new ECC key and test ECDH\n"+
		"\t2: Generate a device key and test ECDH\n"+
		"\t3: Generate a new ECC key and device key, and test ECDH\n\t")
)

func checkOneTrue(options []bool) bool {
	count := 0
	for _, opt := range options {
		if opt {
			count++
		}
	}

	return count == 1
}

func initArgs() {
	flag.Parse()
	logFilePath = *logFile

	selOptions := []bool{*sealKey, *removeKey, *checkCert, *exportEnc, *clrTpm, *tpmInfo, *genKey >= 0, *testTpm >= 0}
	if !checkOneTrue(selOptions) {
		logerr("Passed arguments are mutually exclusive.\n")
		os.Exit(1)
	}

	if *sealKey {
		if *input == "" {
			logerr("input must be specified for seal-key\n")
			os.Exit(1)
		}

		if *pcrHash != "sha1" && *pcrHash != "sha256" {
			logerr("pcr-hash must be sha1 or sha256\n")
			os.Exit(1)
		}

		if *pcrIndexes == "" {
			logerr("pcr-indexes must be non-empty\n")
			os.Exit(1)
		}

		return
	}

	if *genKey >= 0 {
		if *genKey < 0 || *genKey > 5 {
			logerr("invalid gen-key value\n")
			os.Exit(1)
		}

		return
	}

	if *removeKey {
		if *arbitKeyIndex == 0 {
			logerr("key-index must be specified for remove-key\n")
			os.Exit(1)
		}

		return
	}

	if *checkCert {
		if *devCertPath == "" && *devKeyIndex == 0 {
			logerr("cert-path and device key index must be specified\n")
			os.Exit(1)
		}

		return
	}

	if *exportEnc {
		if *output == "" {
			logerr("output must be specified for export\n")
			os.Exit(1)
		}

		if *vpubIndex == 0 || *vprivIndex == 0 || *srkIndex == 0 {
			logerr("vpub-index, vpriv-index and srk-index must be non-zero\n")
			os.Exit(1)
		}

		if *pcrHash != "sha1" && *pcrHash != "sha256" {
			logerr("pcr-hash must be sha1 or sha256\n")
			os.Exit(1)
		}

		if *pcrIndexes == "" {
			logerr("pcr-indexes must be non-empty\n")
			os.Exit(1)
		}
		return
	}
}

func main() {
	initArgs()

	if *sealKey {
		data, err := os.ReadFile(*input)
		if err != nil {
			logerr("error when reading input file: %v\n", err)
			os.Exit(1)
		}

		hashAlgo := tpm2.AlgSHA1
		if *pcrHash == "sha256" {
			hashAlgo = tpm2.AlgSHA256
		}

		pcrs, err := getPcrIndexes(strings.Split(*pcrIndexes, ","))
		if err != nil {
			logerr("error when parsing pcr-indexes argument: %v\n", err)
			os.Exit(1)
		}

		pcrSel := tpm2.PCRSelection{Hash: hashAlgo, PCRs: pcrs}
		err = sealKeyInTpm(data, pcrSel)
		if err != nil {
			logerr("error when sealing key in TPM: %v\n", err)
			os.Exit(1)
		}

		log("Key sealed in TPM.\n")
		return
	}

	if *testTpm >= 0 {
		switch *testTpm {
		case 0:
			err := testEcdhDefaultKeys(*testCount, *showBar)
			if err != nil {
				logerr("error when testing ECDH with default device key and ECC key: %v\n", err)
				os.Exit(1)
			}
		case 1:
			err := testEcdhWithKeyGen(*testCount, *showBar, genECDH, *ecdhIndex, *testRegen)
			if err != nil {
				logerr("error when testing ECDH with generated key: %v\n", err)
				os.Exit(1)
			}
		case 2:
			err := testEcdhWithKeyGen(*testCount, *showBar, genDevKey, *devKeyIndex, *testRegen)
			if err != nil {
				logerr("error when testing ECDH with generated key: %v\n", err)
				os.Exit(1)
			}
		case 3:
			err := testEcdhWithMultiKeyGen(*testCount, *showBar, genDevKey, *devKeyIndex, genECDH, *ecdhIndex, *testRegen)
			if err != nil {
				logerr("error when testing ECDH with multiple generated keys: %v\n", err)
				os.Exit(1)
			}
		default:
			logerr("invalid test value\n")
			os.Exit(1)
		}

		return
	}

	if *genKey >= 0 {
		err := generateKey(*genKey, *arbitKeyIndex)
		if err != nil {
			logerr("error when generating key: %v\n", err)
			os.Exit(1)
		}

		log("Key generated in TPM.\n")
		return
	}

	if *removeKey {
		err := removeKeyFromTpm(tpmutil.Handle(*arbitKeyIndex))
		if err != nil {
			logerr("error when removing key from TPM: %v\n", err)
			os.Exit(1)
		}

		log("Key removed from TPM.\n")
		return
	}

	if *clrTpm {
		err := clearTpm()
		if err != nil {
			log("error when clearing TPM: %v\n", err)
			os.Exit(1)
		}

		log("TPM cleared.\n")
		return
	}

	if *tpmInfo {
		info, err := fetchTpmHwInfo()
		if err != nil {
			logerr("error when fetching TPM info: %v\n", err)
			os.Exit(1)
		}

		log("TPM Info: %s\n", info)
		return
	}

	if *checkCert {
		tpmPublicKey, err := readDeviceKeyPubFromTPM()
		if err != nil {
			logerr("error when reading device public key from TPM: %v\n", err)
			os.Exit(1)
		}

		filePublicKey, err := readDeviceKeyPubFromFile(*devCertPath)
		if err != nil {
			logerr("error when reading device public key from disk: %v\n", err)
			os.Exit(1)
		}

		if reflect.DeepEqual(tpmPublicKey, filePublicKey) {
			log("Device cert from disk matches device cert inside TPM.\n")
		} else {
			log("Device cert from disk does not device cert inside TPM!\n")
		}

		return
	}

	if *exportEnc {
		hashAlgo := tpm2.AlgSHA1
		if *pcrHash == "sha256" {
			hashAlgo = tpm2.AlgSHA256
		}

		pcrs, err := getPcrIndexes(strings.Split(*pcrIndexes, ","))
		if err != nil {
			logerr("error when parsing pcr-indexes argument: %v\n", err)
			os.Exit(1)
		}

		pcrSel := tpm2.PCRSelection{Hash: hashAlgo, PCRs: pcrs}
		encVkey, digest256, err := getEncryptedVaultKey(pcrSel)
		if err != nil {
			logerr("error when getting encrypted vault key: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(string(*output)+".raw", encVkey, 0644); err != nil {
			logerr("error when writing raw formatted key to the output file: %v\n", err)
			os.Exit(1)
		}

		encVkeyWire, err := getVaultKeyWireFormat(encVkey, digest256)
		if err != nil {
			logerr("error when getting cloud formatted key: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(string(*output)+".wire.txt", []byte(encVkeyWire), 0644); err != nil {
			logerr("error when writing wire formatted key to the output file: %v\n", err)
			os.Exit(1)
		}

		log("Vault key saved.\n")
		return
	}
}

func log(format string, args ...interface{}) {
	logto(os.Stdout, format, args...)
}

func logerr(format string, args ...interface{}) {
	logto(os.Stderr, format, args...)
}

func logto(w io.Writer, format string, args ...interface{}) {
	log := fmt.Sprintf(format, args...)
	_, err := w.Write([]byte(log))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error when writing to io.Writer : %v\n", err)
	}

	if logFilePath != "" {
		file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error when opening log file: %v\n", err)
			return
		}
		defer file.Close()

		_, err = file.WriteString(log)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error when writing to log file: %v\n", err)
			return
		}
	}
}

func getPcrIndexes(pcrs []string) ([]int, error) {
	var pcrIndexes []int
	for _, pcr := range pcrs {
		index, err := strconv.Atoi(strings.TrimSpace(pcr))
		if err != nil {
			return nil, fmt.Errorf("invalid PCR index: %v %v", pcr, err)
		}
		pcrIndexes = append(pcrIndexes, index)
	}
	return pcrIndexes, nil
}

func readDeviceKeyPubFromTPM() (crypto.PublicKey, error) {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	deviceKey, _, _, err := tpm2.ReadPublic(rw, tpmutil.Handle(*devKeyIndex))
	if err != nil {
		return nil, err
	}

	publicKey, err := deviceKey.Key()
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func readDeviceKeyPubFromFile(certFile string) (crypto.PublicKey, error) {
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		log("error in reading ecdh cert file: %v", err)
		return nil, err
	}

	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log("error in parsing ecdh cert file: %v", err)
		return nil, err
	}

	return cert.PublicKey, nil
}

func getVaultKeyWireFormat(encryptedVaultKey []byte, digest256 []byte) (string, error) {
	keyData := &attest.AttestVolumeKeyData{
		EncryptedKey: encryptedVaultKey,
		DigestSha256: digest256,
	}

	marshaledVaultKey, err := proto.Marshal(keyData)
	if err != nil {
		return "", fmt.Errorf("error when marshaling AttestVolumeKeyData %v", err)
	}

	key := new(attest.AttestVolumeKey)
	key.KeyType = attest.AttestVolumeKeyType_ATTEST_VOLUME_KEY_TYPE_VSK
	key.Key = marshaledVaultKey

	volumeKey, err := proto.Marshal(key)
	if err != nil {
		return "", fmt.Errorf("error when marshaling AttestVolumeKey %v", err)
	}

	return fmt.Sprintf("0x%X", volumeKey), nil
}

func getEncryptedVaultKey(pcrSel tpm2.PCRSelection) ([]byte, []byte, error) {
	vaultKey, err := getVaultKey(*vprivIndex, *vpubIndex, *srkIndex, pcrSel)
	if err != nil {
		return nil, nil, fmt.Errorf("error when reading from the vault key from TPM: %v", err)
	}

	hash := sha256.New()
	hash.Write(vaultKey)
	digest256 := hash.Sum(nil)

	encryptedVaultKey, err := encryptDecryptUsingTpm(vaultKey, true)
	if err != nil {
		return nil, nil, fmt.Errorf("error when encrypting vault key: %v", err)
	}

	return encryptedVaultKey, digest256, nil
}

func policyPCRSession(rw io.ReadWriteCloser, pcrSel tpm2.PCRSelection) (tpmutil.Handle, []byte, error) {
	session, _, err := tpm2.StartAuthSession(
		rw,
		/*tpmkey=*/ tpm2.HandleNull,
		/*bindkey=*/ tpm2.HandleNull,
		/*nonceCaller=*/ make([]byte, 16),
		/*encryptedSalt=*/ nil,
		/*sessionType=*/ tpm2.SessionPolicy,
		/*symmetric=*/ tpm2.AlgNull,
		/*authHash=*/ tpm2.AlgSHA256)
	if err != nil {
		return tpm2.HandleNull, nil, fmt.Errorf("StartAuthSession failed: %v", err)
	}

	defer func() {
		if session != tpm2.HandleNull && err != nil {
			_ = tpm2.FlushContext(rw, session)
		}
	}()

	if err = tpm2.PolicyPCR(rw, session, nil, pcrSel); err != nil {
		return session, nil, fmt.Errorf("PolicyPCR failed: %v", err)
	}

	policy, err := tpm2.PolicyGetDigest(rw, session)
	if err != nil {
		return session, nil, fmt.Errorf("unable to get policy digest: %v", err)
	}

	return session, policy, nil
}

func getVaultKey(vaultKeyPriv uint, vaultKeyPub uint, tpmSRK uint, pcrSel tpm2.PCRSelection) ([]byte, error) {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	priv, err := tpm2.NVReadEx(rw, tpmutil.Handle(vaultKeyPriv),
		tpm2.HandleOwner, *tpmPass, 0)
	if err != nil {
		return nil, fmt.Errorf("NVReadEx %v failed: %v", vaultKeyPriv, err)
	}

	pub, err := tpm2.NVReadEx(rw, tpmutil.Handle(vaultKeyPub),
		tpm2.HandleOwner, *tpmPass, 0)
	if err != nil {
		return nil, fmt.Errorf("NVReadEx %v failed: %v", vaultKeyPub, err)
	}

	sealedObjHandle, _, err := tpm2.Load(rw, tpmutil.Handle(tpmSRK), "", pub, priv)
	if err != nil {
		return nil, fmt.Errorf("load failed: %v", err)
	}
	defer func() {
		_ = tpm2.FlushContext(rw, sealedObjHandle)
	}()

	session, _, err := policyPCRSession(rw, pcrSel)
	if err != nil {
		return nil, fmt.Errorf("policyPCRSession failed: %v", err)
	}
	defer func() {
		_ = tpm2.FlushContext(rw, session)
	}()

	key, err := tpm2.UnsealWithSession(rw, session, sealedObjHandle, *tpmPass)
	if err != nil {
		return nil, fmt.Errorf("UnsealWithSession failed: %v", err)
	}

	return key, nil
}

func aesEncrypt(ciphertext, plaintext, key, iv []byte) error {
	aesBlockEncrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}

	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
	aesEncrypter.XORKeyStream(ciphertext, plaintext)
	return nil
}

func aesDecrypt(plaintext, ciphertext, key, iv []byte) error {
	aesBlockDecrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return fmt.Errorf("creating aes new cipher failed: %v", err)
	}

	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
	aesDecrypter.XORKeyStream(plaintext, ciphertext)
	return nil
}

func ecdsakeyBytes(pubKey *ecdsa.PublicKey) (int, error) {
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

func rsCombinedBytes(rBytes, sBytes []byte, pubKey *ecdsa.PublicKey) ([]byte, error) {
	keySize, err := ecdsakeyBytes(pubKey)
	if err != nil {
		return nil, fmt.Errorf("RSCombinedBytes: ecdsa key bytes error %v", err)
	}
	rsize := len(rBytes)
	ssize := len(sBytes)
	if rsize > keySize || ssize > keySize {
		return nil, fmt.Errorf("RSCombinedBytes: error. keySize %v, rSize %v, sSize %v", keySize, rsize, ssize)
	}

	// basically the size is 32 bytes. the r and s needs to be both left padded to two 32 bytes slice
	// into a single signature buffer
	buffer := make([]byte, keySize*2)
	startPos := keySize - rsize
	copy(buffer[startPos:], rBytes)
	startPos = keySize*2 - ssize
	copy(buffer[startPos:], sBytes)

	return buffer[:], nil
}

func sha256FromECPoint(X, Y *big.Int, pubKey *ecdsa.PublicKey) ([32]byte, error) {
	var sha [32]byte
	bytes, err := rsCombinedBytes(X.Bytes(), Y.Bytes(), pubKey)
	if err != nil {
		return sha, fmt.Errorf("error occurred while combining bytes for ECPoints: %v", err)
	}

	return sha256.Sum256(bytes), nil
}

func deriveSessionKey(X, Y *big.Int, publicKey *ecdsa.PublicKey) ([32]byte, error) {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return [32]byte{}, fmt.Errorf("TPM open failed: %v", err)
	}
	defer rw.Close()

	p := tpm2.ECPoint{XRaw: X.Bytes(), YRaw: Y.Bytes()}
	z, err := tpm2.ECDHZGen(rw, tpmutil.Handle(*ecdhIndex), "", p)
	if err != nil {
		return [32]byte{}, fmt.Errorf("deriveSessionKey failed: %v", err)
	}

	return sha256FromECPoint(z.X(), z.Y(), publicKey)
}

func deriveEncryptDecryptKey() ([32]byte, error) {
	publicKey, err := readDeviceKeyPubFromTPM()
	if err != nil {
		return [32]byte{}, fmt.Errorf("error in readDevicePubFromTPM: %s", err)
	}

	eccPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return [32]byte{}, fmt.Errorf("not an ECDH compatible key: %T", publicKey)
	}

	EncryptDecryptKey, err := deriveSessionKey(eccPublicKey.X, eccPublicKey.Y, eccPublicKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("EncryptSecretWithDeviceKey failed with %v", err)
	}

	return EncryptDecryptKey, nil
}

func encryptDecryptUsingTpm(in []byte, encrypt bool) ([]byte, error) {
	key, err := deriveEncryptDecryptKey()
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	out := make([]byte, len(in))
	if encrypt {
		err = aesEncrypt(out, in, key[:], iv)
	} else {
		err = aesDecrypt(out, in, key[:], iv)
	}

	return out, err
}

func getTpmProperty(propID tpm2.TPMProp) (uint32, error) {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return 0, err
	}
	defer rw.Close()

	v, _, err := tpm2.GetCapability(rw, tpm2.CapabilityTPMProperties, 1, uint32(propID))
	if err != nil {
		return 0, err
	}
	prop, ok := v[0].(tpm2.TaggedProperty)
	if !ok {
		return 0, fmt.Errorf("fetching TPM property %X failed", propID)
	}
	return prop.Value, nil
}

func getModelName(vendorValue1 uint32, vendorValue2 uint32) string {
	uintToByteArr := func(value uint32) []byte {
		get8 := func(val uint32, offset uint32) uint8 {
			return (uint8)((val >> ((3 - offset) * 8)) & 0xff)
		}
		var i uint32
		var bytes []byte
		for i = 0; i < uint32(unsafe.Sizeof(value)); i++ {
			c := get8(value, i)
			bytes = append(bytes, c)
		}
		return bytes
	}
	var model []byte
	model = append(model, uintToByteArr(vendorValue1)...)
	model = append(model, uintToByteArr(vendorValue2)...)
	return string(model)
}

func getFirmwareVersion(v1 uint32, v2 uint32) string {
	get16 := func(val uint32, offset uint32) uint16 {
		return uint16((val >> ((1 - offset) * 16)) & 0xFFFF)
	}
	return fmt.Sprintf("%d.%d.%d.%d", get16(v1, 0), get16(v1, 1),
		get16(v2, 0), get16(v2, 1))
}

func fetchTpmHwInfo() (string, error) {
	//First time. Fetch it from TPM and cache it.
	v1, err := getTpmProperty(tpmPropertyManufacturer)
	if err != nil {
		return "", err
	}
	v2, err := getTpmProperty(tpmPropertyVendorStr1)
	if err != nil {
		return "", err
	}
	v3, err := getTpmProperty(tpmPropertyVendorStr2)
	if err != nil {
		return "", err
	}
	v4, err := getTpmProperty(tpmPropertyFirmVer1)
	if err != nil {
		return "", err
	}
	v5, err := getTpmProperty(tpmPropertyFirmVer2)
	if err != nil {
		return "", err
	}
	tpmHwInfo := fmt.Sprintf("%s-%s, FW Version %s", vendorRegistry[v1],
		getModelName(v2, v3),
		getFirmwareVersion(v4, v5))

	return tpmHwInfo, nil
}

func clearTpm() error {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return fmt.Errorf("error in opening TPM: %v", err)
	}
	defer rw.Close()

	auth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	err = tpm2.Clear(rw, tpm2.HandleLockout, auth)
	if err != nil {
		return fmt.Errorf("error in clearing TPM: %v", err)
	}
	return nil
}

func createKey(keyHandle tpmutil.Handle, OwnerCred string, template tpm2.Public) error {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return err
	}
	defer rw.Close()

	handle, _, err := tpm2.CreatePrimary(rw,
		tpm2.HandleOwner,
		pcrSelection,
		*tpmPass,
		OwnerCred,
		template)
	if err != nil {
		return fmt.Errorf("create 0x%x failed: %s, do BIOS reset of TPM", keyHandle, err)
	}

	// remove the old index if it exists
	_ = tpm2.EvictControl(rw, *tpmPass,
		tpm2.HandleOwner,
		keyHandle,
		keyHandle)

	if err := tpm2.EvictControl(rw, *tpmPass,
		tpm2.HandleOwner, handle,
		keyHandle); err != nil {
		return fmt.Errorf("EvictControl failed: %v, do BIOS reset of TPM", err)
	}

	return nil
}

func readOwnerCrdl() (string, error) {
	tpmOwnerPasswdBytes, err := os.ReadFile(*tpmCredPath)
	if err != nil {
		return "", err
	}
	tpmOwnerPasswd := string(tpmOwnerPasswdBytes)
	if len(tpmOwnerPasswd) > tpmMaxPasswdLength {
		tpmOwnerPasswd = tpmOwnerPasswd[0:tpmMaxPasswdLength]
	}
	return tpmOwnerPasswd, nil
}

func removeKeyFromTpm(keyHandle tpmutil.Handle) error {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return err
	}
	defer rw.Close()

	err = tpm2.EvictControl(rw, *tpmPass,
		tpm2.HandleOwner,
		keyHandle,
		keyHandle)
	if err != nil {
		return fmt.Errorf("EvictControl failed: %v", err)
	}
	return nil
}

func sealKeyInTpm(data []byte, pcrSel tpm2.PCRSelection) error {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return err
	}
	defer rw.Close()

	_ = tpm2.NVUndefineSpace(rw, *tpmPass,
		tpm2.HandleOwner, tpmutil.Handle(*vprivIndex))

	_ = tpm2.NVUndefineSpace(rw, *tpmPass,
		tpm2.HandleOwner, tpmutil.Handle(*vpubIndex))

	session, policy, err := policyPCRSession(rw, pcrSel)
	if err != nil {
		return fmt.Errorf("PolicyPCRSession failed: %w", err)
	}

	if err := tpm2.FlushContext(rw, session); err != nil {
		return fmt.Errorf("flushing session handle %v failed: %w", session, err)
	}

	priv, public, err := tpm2.Seal(rw, tpmutil.Handle(*srkIndex), *tpmPass, *tpmPass, policy, data)
	if err != nil {
		return fmt.Errorf("sealing the disk key into TPM failed: %w", err)
	}

	if err := tpm2.NVDefineSpace(rw,
		tpm2.HandleOwner,
		tpmutil.Handle(*vprivIndex),
		*tpmPass,
		*tpmPass,
		nil,
		tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead,
		uint16(len(priv)),
	); err != nil {
		return fmt.Errorf("NVDefineSpace %v failed: %w", tpmutil.Handle(*vprivIndex), err)
	}

	if err := tpm2.NVWrite(rw, tpm2.HandleOwner, tpmutil.Handle(*vprivIndex),
		*tpmPass, priv, 0); err != nil {
		return fmt.Errorf("NVWrite %v failed: %w", tpmutil.Handle(*vprivIndex), err)
	}

	if err := tpm2.NVDefineSpace(rw,
		tpm2.HandleOwner,
		tpmutil.Handle(*vpubIndex),
		*tpmPass,
		*tpmPass,
		nil,
		tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead,
		uint16(len(public)),
	); err != nil {
		return fmt.Errorf("NVDefineSpace %v failed: %w", tpmutil.Handle(*vpubIndex), err)
	}

	if err := tpm2.NVWrite(rw, tpm2.HandleOwner, tpmutil.Handle(*vpubIndex),
		*tpmPass, public, 0); err != nil {
		return fmt.Errorf("NVWrite %v failed: %w", tpmutil.Handle(*vpubIndex), err)
	}

	return nil
}

func getGenKeyDefaults(key int) (tpm2.Public, tpmutil.Handle) {
	switch key {
	case 0:
		return defaultKeyParams, tpmDeviceKeyHdl
	case 1:
		return defaultEkTemplate, tpmEKHdl
	case 2:
		return defaultSrkTemplate, tpmSRKHdl
	case 3:
		return defaultAkTemplate, tpmAKHdl
	case 4:
		return defaultQuoteKeyTemplate, tpmQuoteKeyHdl
	case 5:
		return defaultEcdhKeyTemplate, tpmEcdhKeyHdl
	}

	return tpm2.Public{}, tpmutil.Handle(0)
}

func generateKey(key int, index uint) error {
	ownerCred := ""
	keyTemplate, keyHandle := getGenKeyDefaults(key)
	if index != 0 {
		keyHandle = tpmutil.Handle(index)
	}

	// device key needs owner credential
	if key == 0 {
		cred, err := readOwnerCrdl()
		if err != nil {
			return fmt.Errorf("gen key failed while reading owner credential: %v", err)
		}
		ownerCred = cred
	}

	err := createKey(keyHandle, ownerCred, keyTemplate)
	if err != nil {
		return fmt.Errorf("error when creating key in TPM: %v", err)
	}

	return nil
}

func testECDH() error {
	// only key derivation happens in TPM,
	// encryption part is software and doesn't matter int this case.
	_, err := deriveEncryptDecryptKey()
	if err != nil {
		return err
	}

	return nil
}

func testEcdhDefaultKeys(counter int, showBar bool) error {
	var bar *progressbar.ProgressBar
	if showBar {
		bar = progressbar.Default(int64(counter))
	}

	for i := 0; i < counter; i++ {
		err := testECDH()
		if err != nil {
			return fmt.Errorf("error when testing ECDH: %v", err)
		}

		if showBar {
			_ = bar.Add(1)
		}
	}

	return nil
}

func testEcdhWithKeyGen(counter int, showBar bool, key int, index uint, regen bool) error {
	var bar *progressbar.ProgressBar
	if showBar {
		bar = progressbar.Default(int64(counter))
	}

	// generate ecc key
	err := generateKey(key, index)
	if err != nil {
		return fmt.Errorf("error when generating key: %v", err)
	}

	for i := 0; i < counter; i++ {
		if i > 0 && regen {
			err := generateKey(key, index)
			if err != nil {
				return fmt.Errorf("error when generating key: %v", err)
			}
		}

		err := testECDH()
		if err != nil {
			return fmt.Errorf("error when testing ECDH: %v", err)
		}

		if showBar {
			_ = bar.Add(1)
		}
	}

	return nil
}

func testEcdhWithMultiKeyGen(counter int, showBar bool, keyOne int, indexOne uint, keyTwo int, indexTwo uint, regen bool) error {
	var bar *progressbar.ProgressBar
	if showBar {
		bar = progressbar.Default(int64(counter))
	}

	err := generateKey(keyOne, indexOne)
	if err != nil {
		return fmt.Errorf("error when generating key one: %v", err)
	}

	err = generateKey(keyTwo, indexTwo)
	if err != nil {
		return fmt.Errorf("error when generating key two: %v", err)
	}

	for i := 0; i < counter; i++ {
		if i > 0 && regen {
			err := generateKey(keyOne, indexOne)
			if err != nil {
				return fmt.Errorf("error when generating key one : %v", err)
			}

			err = generateKey(keyTwo, indexTwo)
			if err != nil {
				return fmt.Errorf("error when generating key two: %v", err)
			}
		}

		err := testECDH()
		if err != nil {
			return fmt.Errorf("error when testing ECDH: %v", err)
		}

		if showBar {
			_ = bar.Add(1)
		}
	}

	return nil
}
