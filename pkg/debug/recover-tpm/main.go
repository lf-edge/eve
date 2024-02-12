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

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/api/go/attest"
	"google.golang.org/protobuf/proto"
)

var logFilePath string

var (
	tpmPath         = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device)")
	tpmPass         = flag.String("tpm-pass", "", "TPM device password (if needed)")
	pubIndex        = flag.Uint("pub-index", 0, "Vault key public key NVRAM index")
	privIndex       = flag.Uint("priv-index", 0, "Vault Key private key NVRAM index")
	srkIndex        = flag.Uint("srk-index", 0, "Storage Root Key (SRK) index")
	ecdhIndex       = flag.Uint("ecdh-index", 0, "ECDH key index")
	certIndex       = flag.Uint("cert-index", 0, "Device key (aka device cert) index")
	certPath        = flag.String("cert-path", "", "Path to the device cert file")
	pcrHash         = flag.String("pcr-hash", "sha1", "PCR Hash algorithm (sha1, sha256)")
	pcrIndexes      = flag.String("pcr-index", "0", "PCR Indexes to use for sealing and unsealing")
	exportPlain     = flag.Bool("export-plain", false, "Export the vault key in plain text")
	exportCloud     = flag.Bool("export-cloud", false, "Export the vault key in cloud encrypted form")
	importPlain     = flag.Bool("import-plain", false, "Import the vault key in plain text")
	importEncrypted = flag.Bool("import-encrypted", false, "Import the vault key in encrypted form")
	reseal          = flag.Bool("reseal", false, "Reseal the vault key under new PCR indexes and hash algorithm")
	output          = flag.String("output", "", "Output file for the vault key")
	input           = flag.String("input", "", "Input file for the vault key")
	checkCert       = flag.Bool("check-cert", false, "Compare the device cert from vault with the device cert inside TPM")
	logFile         = flag.String("log", "", "log file path")
)

func main() {
	initArgs()

	if *checkCert {
		tpmPublicKey, err := readDevicePubFromTPM()
		if err != nil {
			log("[!] error when reading device public key from TPM: %v\n", err)
			os.Exit(1)
		}

		filePublicKey, err := readDevicePubFromFile(*certPath)
		if err != nil {
			log("[!] error when reading device public key from disk: %v\n", err)
			os.Exit(1)
		}

		if reflect.DeepEqual(tpmPublicKey, filePublicKey) {
			log("[+] Device cert from disk matches device cert inside TPM.\n")
		} else {
			log("[!] Device cert from disk does not device cert inside TPM.!!!\n")
		}

		return
	}

	hashAlgo := tpm2.AlgSHA1
	if *pcrHash == "sha256" {
		hashAlgo = tpm2.AlgSHA256
	}

	pcrs, err := getPcrIndexes(strings.Split(*pcrIndexes, ","))
	if err != nil {
		log("[!] error when parsing pcr-indexes argument: %v\n", err)
		os.Exit(1)
	}

	vaultKey := make([]byte, 0)
	if *exportCloud || *exportPlain {
		pcrSel := tpm2.PCRSelection{Hash: hashAlgo, PCRs: pcrs}
		vaultKey, err = getVaultKey(uint32(*privIndex), uint32(*pubIndex), uint32(*srkIndex), pcrSel)
		if err != nil {
			log("[!] error when reading from the vault key from TPM: %v\n", err)
			os.Exit(1)
		}

		log("[+] Vault key available and exportable.\n")
	}

	// Export the vault key to the output file in plain text
	if *exportPlain && *output != "" {
		log("[+] Saving vault key to %s\n", *output)
		if err := os.WriteFile(string(*output), vaultKey, 0644); err != nil {
			log("[!] error when writing to the output file: %v\n", err)
			os.Exit(1)
		}

		log("[+] Vault key saved.\n")
	}

	if *exportCloud && *output != "" {
		log("[+] Saving cloud-format encrypted vault key...\n")

		encryptedVaultKey, err := encryptDecryptUsingTpm(vaultKey, true)
		if err != nil {
			log("[!] error when encrypting vault key: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(string(*output)+".raw", encryptedVaultKey, 0644); err != nil {
			log("[!] error when writing raw formatted key to the output file: %v\n", err)
			os.Exit(1)
		}

		hash := sha256.New()
		hash.Write(vaultKey)
		digest256 := hash.Sum(nil)

		keyData := &attest.AttestVolumeKeyData{
			EncryptedKey: encryptedVaultKey,
			DigestSha256: digest256,
		}

		marshaledVaultKey, err := proto.Marshal(keyData)
		if err != nil {
			log("[!] error when marshaling AttestVolumeKeyData %v", err)
			os.Exit(1)
		}

		key := new(attest.AttestVolumeKey)
		key.KeyType = attest.AttestVolumeKeyType_ATTEST_VOLUME_KEY_TYPE_VSK
		key.Key = marshaledVaultKey

		volumeKey, err := proto.Marshal(key)
		if err != nil {
			log("[!] error when marshaling AttestVolumeKey %v", err)
			os.Exit(1)
		}

		cloudDbFormat := fmt.Sprintf("0x%X", volumeKey)
		if err := os.WriteFile(string(*output)+".txt", []byte(cloudDbFormat), 0644); err != nil {
			log("[!] error when writing cloud formatted key to the output file: %v\n", err)
			os.Exit(1)
		}

		log("[+] Vault key saved.\n")
	}

	if *reseal {
		log("[!] not implemented yet...\n")
		os.Exit(1)
	}

	if *importPlain || *importEncrypted {
		log("[!] not implemented yet...\n")
		os.Exit(1)
	}

	// TODO :
	// Import the vault key from the input file
	// Reseal the vault key under new PCR indexes and hash algorithm
}

func initArgs() {
	flag.Parse()

	if *checkCert {
		if *certPath == "" && *certIndex == 0 {
			fmt.Fprintln(os.Stderr, "cert-path and cert-index must be specified for check-cert")
			os.Exit(1)
		}
	} else {
		if !*exportPlain && !*importPlain && !*importEncrypted && !*reseal && !*exportCloud {
			fmt.Fprintln(os.Stderr, "One of export-*/import-* or reseal must be specified")
			os.Exit(1)
		}

		if (*importPlain || *importEncrypted) && *input == "" {
			fmt.Fprintln(os.Stderr, "import commands requires input to be specified")
			os.Exit(1)
		}

		if *importPlain && *importEncrypted {
			fmt.Fprintln(os.Stderr, "import-plain and import-encrypted are mutually exclusive")
			os.Exit(1)
		}

		if *pubIndex == 0 || *privIndex == 0 || *srkIndex == 0 {
			fmt.Fprintln(os.Stderr, "pub-index, priv-index and srk-index must be non-zero")
			os.Exit(1)
		}

		if *pcrHash != "sha1" && *pcrHash != "sha256" {
			fmt.Fprintln(os.Stderr, "pcr-hash must be sha1 or sha256")
			os.Exit(1)
		}

		if *pcrIndexes == "" {
			fmt.Fprintln(os.Stderr, "pcr-indexes must be non-empty")
			os.Exit(1)
		}

		if *exportCloud && *output == "" {
			fmt.Fprintln(os.Stderr, "output must be specified for export-cloud")
			os.Exit(1)
		}

		if *exportCloud && *certIndex == 0 {
			fmt.Fprintln(os.Stderr, "cert-index must be non-zero for export-cloud")
			os.Exit(1)
		}
	}

	logFilePath = *logFile
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

func getVaultKey(vaultKeyPriv uint32, vaultKeyPub uint32, tpmSRK uint32, pcrSel tpm2.PCRSelection) ([]byte, error) {
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
	//Recover the key, and decrypt the message
	z, err := tpm2.ECDHZGen(rw, tpmutil.Handle(*ecdhIndex), "", p)
	if err != nil {
		return [32]byte{}, fmt.Errorf("deriveSessionKey failed: %v", err)
	}

	return sha256FromECPoint(z.X(), z.Y(), publicKey)
}

func readDevicePubFromTPM() (crypto.PublicKey, error) {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	deviceKey, _, _, err := tpm2.ReadPublic(rw, tpmutil.Handle(*certIndex))
	if err != nil {
		return nil, err
	}

	publicKey, err := deviceKey.Key()
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func readDevicePubFromFile(certFile string) (crypto.PublicKey, error) {
	//read public key from ecdh certificate
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

func deriveEncryptDecryptKey() ([32]byte, error) {
	publicKey, err := readDevicePubFromTPM()
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

func log(format string, args ...interface{}) {
	log := fmt.Sprintf(format, args...)
	fmt.Println(log)

	if logFilePath != "" {
		file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error when opening log file: %v\n", err)
			return
		}
		defer file.Close()

		_, err = file.WriteString(log + "\n")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error when writing to log file: %v\n", err)
			return
		}
	}
}
