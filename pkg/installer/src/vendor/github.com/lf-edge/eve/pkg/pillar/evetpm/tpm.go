// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"unsafe"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

const (
	//TpmPasswdHdl is the well known TPM NVIndex for TPM Credentials
	TpmPasswdHdl tpmutil.Handle = 0x1600000

	//TpmEKHdl is the well known TPM permanent handle for Endorsement key
	TpmEKHdl tpmutil.Handle = 0x81000001

	//TpmSRKHdl is the well known TPM permanent handle for Storage key
	TpmSRKHdl tpmutil.Handle = 0x81000002

	//TpmAIKHdl is the well known TPM permanent handle for AIK key
	TpmAIKHdl tpmutil.Handle = 0x81000003

	//TpmQuoteKeyHdl is the well known TPM permanent handle for PCR Quote signing key
	TpmQuoteKeyHdl tpmutil.Handle = 0x81000004

	//TpmEcdhKeyHdl is the well known TPM permanent handle for ECDH key
	TpmEcdhKeyHdl tpmutil.Handle = 0x81000005

	//TpmDeviceKeyHdl is the well known TPM permanent handle for device key
	TpmDeviceKeyHdl tpmutil.Handle = 0x817FFFFF

	//TpmCredentialsFileName is the file that holds the dynamically created TPM credentials
	TpmCredentialsFileName = types.IdentityDirname + "/tpm_credential"

	//MaxPasswdLength is the max length allowed for a TPM password
	MaxPasswdLength = 7 //limit TPM password to this length

	//TpmDiskKeyHdl is the handle for constructing disk encryption key
	TpmDiskKeyHdl tpmutil.Handle = 0x1700000

	//TpmDeviceCertHdl is the well known TPM NVIndex for device cert
	TpmDeviceCertHdl tpmutil.Handle = 0x1500000

	//TpmSealedDiskPrivHdl is the handle for constructing disk encryption key
	TpmSealedDiskPrivHdl tpmutil.Handle = 0x1800000

	//TpmSealedDiskPubHdl is the handle for constructing disk encryption key
	TpmSealedDiskPubHdl tpmutil.Handle = 0x1900000

	//EmptyPassword is an empty string
	EmptyPassword  = ""
	vaultKeyLength = 32 //Bytes
)

// PCRBank256Status stores info about support for
// SHA256 PCR bank on this device
type PCRBank256Status uint32

// Different values for PCRBank256Status
const (
	PCRBank256StatusUnknown PCRBank256Status = iota + 0
	PCRBank256StatusSupported
	PCRBank256StatusNotSupported
)

var (
	//EcdhKeyFile is the location of the ecdh private key
	//on devices without a TPM. It is not a constant due to test usage
	EcdhKeyFile = types.CertificateDirname + "/ecdh.key.pem"

	tpmHwInfo        = ""
	pcrBank256Status = PCRBank256StatusUnknown

	//DiskKeySealingPCRs represents PCRs that we use for sealing
	DiskKeySealingPCRs = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 1, 2, 3, 4, 6, 7, 8, 9, 13, 14}}

	// TpmDevicePath is the TPM device file path, it is not a constant due to
	// test usage.
	TpmDevicePath = "/dev/tpmrm0"

	// measurementLogFile is a kernel exposed variable that contains the
	// TPM measurements and events log. it is not a constant due to test usage.
	measurementLogFile = "/hostfs/sys/kernel/security/tpm0/binary_bios_measurements"

	// savedSealingPcrsFile is the file that holds a copy of PCR values at the
	// time of generating and sealing the disk key into the TPM. it is not a
	// constant due to test usage.
	savedSealingPcrsFile = types.PersistStatusDir + "/sealingpcrs"

	// measurementLogSealSuccess is files that holds a copy of event log at the
	// time of generating/sealing the disk key into the TPM. it is not a constant
	// due to test usage.
	measurementLogSealSuccess = types.PersistStatusDir + "/tpm_measurement_seal_success"

	// measurementLogUnsealFail is files that holds a copy of event log at the
	// time EVE fails to unseal the vault key from TPM. it is not a constant due
	// to test usage.
	measurementLogUnsealFail = types.PersistStatusDir + "/tpm_measurement_unseal_fail"

	// measurefsTpmEventLog is the file containing the event log from the measure-config.
	// it is not a constant due to test usage.
	measurefsTpmEventLog = types.PersistStatusDir + "/measurefs_tpm_event_log"

	// PcrSelection is used as an entropy to generate keys and the selection
	// of PCRs do not matter as well as the contents but PCR[7] is not changed often
	// on our devices
	PcrSelection = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7}}
	// PcrListForQuote is PCR selection for Quote operation in attestation process.
	PcrListForQuote = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}}

	// DefaultKeyParams is the default Key Template for TPM
	DefaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagNoDA | tpm2.FlagDecrypt |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
		},
	}
	// DefaultEkTemplate is the default Ek Template as per
	// https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
	DefaultEkTemplate = tpm2.Public{
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
	// DefaultSrkTemplate is for ActivateCredentials() usage (Decrypt key)
	DefaultSrkTemplate = tpm2.Public{
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
	// DefaultAikTemplate is a restricted signing key, for vTPM guest usage
	DefaultAikTemplate = tpm2.Public{
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
	// DefaultQuoteKeyTemplate is a restricted signing key, for PCR Quote and other such uses
	DefaultQuoteKeyTemplate = tpm2.Public{
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
	// DefaultEcdhKeyTemplate is used for deriving AES keys
	DefaultEcdhKeyTemplate = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagNoDA | tpm2.FlagDecrypt |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
		},
	}
)

// SealedKeyType holds different types of sealed key
// defined below
type SealedKeyType uint32

// Different sealed key types, for logging purposes
const (
	SealedKeyTypeUnknown     SealedKeyType = iota + 0 //Invalid
	SealedKeyTypeReused                               //Sealed key is cloned from legacy key
	SealedKeyTypeNew                                  //Sealed key is not cloned from legacy key
	SealedKeyTypeUnprotected                          //Sealed key is not available, using legacy key
)

// String returns verbose string for SealedKeyType value
func (s SealedKeyType) String() string {
	switch s {
	case SealedKeyTypeUnknown:
		return "Unsealing failed"
	case SealedKeyTypeReused:
		return "Key is copied and protected using PCRs"
	case SealedKeyTypeNew:
		return "Key is new and protected using PCRs"
	case SealedKeyTypeUnprotected:
		return "Key is unprotected, because PCR-SHA256 bank is absent"
	default:
		return "Unknown type, this is an implementation error"
	}
}

// TpmPrivateKey is Custom implementation of crypto.PrivateKey interface
type TpmPrivateKey struct {
	PublicKey crypto.PublicKey
}

// Helper structure to pack ecdsa signature for ASN1 encoding
type ecdsaSignature struct {
	R, S *big.Int
}

var myDevicePublicKey crypto.PublicKey

// SetDevicePublicKey is needed for the self-signed bootstrap
func SetDevicePublicKey(pubkey crypto.PublicKey) {
	myDevicePublicKey = pubkey
}

// Public implements crypto.PrivateKey interface
func (s TpmPrivateKey) Public() crypto.PublicKey {
	if myDevicePublicKey != nil {
		ecdsaPublicKey := myDevicePublicKey.(*ecdsa.PublicKey)
		return ecdsaPublicKey
	}
	clientCertBytes, err := os.ReadFile(types.DeviceCertName)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(clientCertBytes)
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	ecdsaPublicKey := cert.PublicKey.(*ecdsa.PublicKey)
	return ecdsaPublicKey
}

// Sign implements crypto.PrivateKey interface
func (s TpmPrivateKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	R, S, err := TpmSign(digest)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ecdsaSignature{R, S})
}

// CreateKey helps creating various keys, according to the supplied template, and hierarchy,
// we pass TPM path here because in some places we pass socket rather than char device.
func CreateKey(log *base.LogObject, TpmPath string, keyHandle, ownerHandle tpmutil.Handle, template tpm2.Public, overwrite bool) error {
	rw, err := tpm2.OpenTPM(TpmPath)
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
		PcrSelection,
		EmptyPassword,
		EmptyPassword,
		template)
	if err != nil {
		return fmt.Errorf("create 0x%x failed: %s, do BIOS reset of TPM", keyHandle, err)
	}
	// This call tries to remove the old index if it exists,
	// so no harm if it fails.
	if err := tpm2.EvictControl(rw, EmptyPassword, tpm2.HandleOwner, keyHandle, keyHandle); err != nil {
		log.Warnf("EvictControl failed: %v", err)
	}
	if err := tpm2.EvictControl(rw, EmptyPassword, tpm2.HandleOwner, handle, keyHandle); err != nil {
		return fmt.Errorf("EvictControl failed: %v, do BIOS reset of TPM", err)
	}

	return nil
}

// ReadOwnerCrdl returns credential specific to this device
func ReadOwnerCrdl() (string, error) {
	tpmOwnerPasswdBytes, err := os.ReadFile(TpmCredentialsFileName)
	if err != nil {
		return "", err
	}
	tpmOwnerPasswd := string(tpmOwnerPasswdBytes)
	if len(tpmOwnerPasswd) > MaxPasswdLength {
		tpmOwnerPasswd = tpmOwnerPasswd[0:MaxPasswdLength]
	}
	return tpmOwnerPasswd, nil
}

// TpmSign is used by external packages to get a digest signed by
// device key in TPM
func TpmSign(digest []byte) (*big.Int, *big.Int, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return nil, nil, err
	}
	defer rw.Close()

	tpmOwnerPasswd, err := ReadOwnerCrdl()
	if err != nil {
		return nil, nil, fmt.Errorf("fetching TPM credentials failed: %w", err)
	}

	//XXX This "32" should really come from Hash algo used.
	if len(digest) > 32 {
		digest = digest[:32]
	}

	scheme := &tpm2.SigScheme{
		Alg:  tpm2.AlgECDSA,
		Hash: tpm2.AlgSHA256,
	}
	sig, err := tpm2.Sign(rw, TpmDeviceKeyHdl,
		tpmOwnerPasswd, digest, nil, scheme)
	if err != nil {
		return nil, nil, fmt.Errorf("signing data using TPM failed: %w", err)
	}
	return sig.ECC.R, sig.ECC.S, nil
}

// IsTpmEnabled checks if TPM is being used by software for creating device cert
// Note that this must not be called before the device certificate has been generated
func IsTpmEnabled() bool {
	return fileutils.FileExists(nil, types.DeviceCertName) &&
		!fileutils.FileExists(nil, types.DeviceKeyName)
}

// GetRandom returns a random []byte of requested length
func GetRandom(numBytes uint16) ([]byte, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return nil, err
	}
	defer rw.Close()
	return tpm2.GetRandom(rw, numBytes)
}

// GetModelName combines vendor1 and vendor2 values into a string
func GetModelName(vendorValue1 uint32, vendorValue2 uint32) string {
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

// GetFirmwareVersion converts v1, v2 values from TPM properties to string
func GetFirmwareVersion(v1 uint32, v2 uint32) string {
	get16 := func(val uint32, offset uint32) uint16 {
		return uint16((val >> ((1 - offset) * 16)) & 0xFFFF)
	}
	return fmt.Sprintf("%d.%d.%d.%d", get16(v1, 0), get16(v1, 1),
		get16(v2, 0), get16(v2, 1))
}

// GetTpmProperty fetches a given property id, and returns it as uint32
func GetTpmProperty(propID tpm2.TPMProp) (uint32, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return 0, err
	}
	defer rw.Close()

	v, _, err := tpm2.GetCapability(rw, tpm2.CapabilityTPMProperties,
		1, uint32(propID))
	if err != nil {
		return 0, err
	}
	prop, ok := v[0].(tpm2.TaggedProperty)
	if !ok {
		return 0, fmt.Errorf("fetching TPM property %X failed", propID)
	}
	return prop.Value, nil
}

// FetchTpmSwStatus returns states reflecting SW usage of TPM
func FetchTpmSwStatus() info.HwSecurityModuleStatus {
	if _, err := os.Stat(TpmDevicePath); err != nil {
		//No TPM found on this system
		return info.HwSecurityModuleStatus_NOTFOUND
	}
	if IsTpmEnabled() {
		//TPM is found and is used by software
		return info.HwSecurityModuleStatus_ENABLED
	}

	//TPM is found but not being used by software
	return info.HwSecurityModuleStatus_DISABLED
}

// Refer to https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Version-1.01-Revision-1.00.pdf
// These byte sequences in uint32 format is actually ASCII representation of TPM
// vendor ID. Since they are abbreviated names, we are having a map here to show
// a more verbose form of vendor name
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

// till we have next version of go-tpm released, use this
const (
	tpmPropertyManufacturer tpm2.TPMProp = 0x105
	tpmPropertyVendorStr1   tpm2.TPMProp = 0x106
	tpmPropertyVendorStr2   tpm2.TPMProp = 0x107
	tpmPropertyFirmVer1     tpm2.TPMProp = 0x10b
	tpmPropertyFirmVer2     tpm2.TPMProp = 0x10c
)

// FetchTpmHwInfo returns TPM Hardware properties in a string
func FetchTpmHwInfo() (string, error) {
	//If we had done this earlier, return the last result
	if tpmHwInfo != "" {
		return tpmHwInfo, nil
	}

	//Take care of non-TPM platforms
	if _, err := os.Stat(TpmDevicePath); err != nil {
		tpmHwInfo = "Not Available"
		//nolint:nilerr
		return tpmHwInfo, nil
	}

	//First time. Fetch it from TPM and cache it.
	v1, err := GetTpmProperty(tpmPropertyManufacturer)
	if err != nil {
		return "", err
	}
	v2, err := GetTpmProperty(tpmPropertyVendorStr1)
	if err != nil {
		return "", err
	}
	v3, err := GetTpmProperty(tpmPropertyVendorStr2)
	if err != nil {
		return "", err
	}
	v4, err := GetTpmProperty(tpmPropertyFirmVer1)
	if err != nil {
		return "", err
	}
	v5, err := GetTpmProperty(tpmPropertyFirmVer2)
	if err != nil {
		return "", err
	}
	tpmHwInfo = fmt.Sprintf("%s-%s, FW Version %s", vendorRegistry[v1],
		GetModelName(v2, v3),
		GetFirmwareVersion(v4, v5))

	return tpmHwInfo, nil
}

// FetchVaultKey retrieves TPM part of the vault key
func FetchVaultKey(log *base.LogObject) ([]byte, error) {
	//First try to read from TPM, if it was stored earlier
	key, err := readDiskKey()
	if err != nil {
		log.Noticef("can't read the legacy disk key, generating a new one")
		//
		//Note on why we are using GetRandom here:
		//We are using raw_key option to protect the encryption/decryption protector:
		//https://github.com/google/fscrypt#using-a-raw-key-protector
		//
		//fscrypt wants a random 32-byte binary value as the raw key value. It uses
		//it as a seed to further derive an AES key which will then protect the actual
		//key used in encryption and decryption of the data on disk.
		//
		//To satisfy randomness, we are using TPM's native RNG component (preferred
		//over /dev/urandom):
		//https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part1_Architecture_pub.pdf
		//
		//The name "key" may be confusing here, as in it is not a key per se. It is a seed value AFAIK.
		//But that is what fscrypt uses, so I borrowed the same term for uniformity.
		//
		key, err = GetRandom(vaultKeyLength)
		if err != nil {
			return nil, fmt.Errorf("GetRandom failed: %w", err)
		}
		err = writeDiskKey(key)
		if err != nil {
			return nil, fmt.Errorf("writing legacy Key to TPM failed: %w", err)
		}
	} else {
		log.Noticef("successfully read the legacy disk key from TPM")
	}
	return key, nil
}

func writeDiskKey(key []byte) error {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()

	//not an error if it fails
	tpm2.NVUndefineSpace(rw, EmptyPassword,
		tpm2.HandleOwner, TpmDiskKeyHdl)

	// Define space in NV storage and clean up afterwards or subsequent runs will fail.
	if err := tpm2.NVDefineSpace(rw,
		tpm2.HandleOwner,
		TpmDiskKeyHdl,
		EmptyPassword,
		EmptyPassword,
		nil,
		tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead,
		uint16(len(key)),
	); err != nil {
		return fmt.Errorf("NVDefineSpace failed: %w", err)
	}

	// Write the data
	if err := tpm2.NVWrite(rw, tpm2.HandleOwner, TpmDiskKeyHdl,
		EmptyPassword, key, 0); err != nil {
		return fmt.Errorf("NVWrite failed: %w", err)
	}
	return nil
}

func readDiskKey() ([]byte, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	// Read all of the data with NVReadEx
	keyBytes, err := tpm2.NVReadEx(rw, TpmDiskKeyHdl,
		tpm2.HandleOwner, EmptyPassword, 0)
	if err != nil {
		return nil, fmt.Errorf("NVReadEx failed: %w", err)
	}
	return keyBytes, nil
}

// FetchSealedVaultKey fetches Vault key sealed into TPM2.0
func FetchSealedVaultKey(log *base.LogObject) ([]byte, error) {
	if !PCRBankSHA256Enabled() {
		//On platforms without PCR Bank SHA256, we can't
		//generate a sealed key. On those platforms,
		//FetchSealedVaultKey becomes FetchVaultKey.
		//Ideally we should not reach here if we are
		//creating vault for the first time, this is to
		//handle upgrade scenario, where vault is already
		//present with legacy key, and we are trying to
		//move it to a sealed one.
		return FetchVaultKey(log)
	}

	//gain some knowledge about existing environment
	sealedKeyPresent := isSealedKeyPresent()
	legacyKeyPresent := isLegacyKeyPresent()

	if !sealedKeyPresent && !legacyKeyPresent {
		log.Noticef("neither legacy nor sealed disk key present, generating a fresh key")
		//Fresh install, generate a new key
		//
		//Note on why we are using GetRandom here:
		//We are using raw_key option to protect the encryption/decryption protector:
		//https://github.com/google/fscrypt#using-a-raw-key-protector
		//
		//fscrypt wants a random 32-byte binary value as the raw key value. It uses
		//it as a seed to further derive an AES key which will then protect the actual
		//key used in encryption and decryption of the data on disk.
		//
		//To satisfy randomness, we are using TPM's native RNG component (preferred
		//over /dev/urandom):
		//https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part1_Architecture_pub.pdf
		//
		//The name "key" may be confusing here, as in it is not a key per se. It is a seed value AFAIK.
		//But that is what fscrypt uses, so I borrowed the same term for uniformity.
		//
		key, err := GetRandom(vaultKeyLength)
		if err != nil {
			return nil, fmt.Errorf("GetRandom failed: %w", err)
		}
		err = SealDiskKey(log, key, DiskKeySealingPCRs)
		if err != nil {
			return nil, fmt.Errorf("sealing the fresh disk key failed: %w", err)
		}

		log.Noticef("successfully sealed the fresh disk key into TPM")
	}

	if !sealedKeyPresent && legacyKeyPresent {
		log.Noticef("only legacy disk key present, using it")
		//XXX: we need a migration path for existing installations.
		//hence re-using the current key here. i.e. if we end up creating
		//a new random key here, and we fail the upgrade, the fallback
		//image will not be able to unlock the vault, and we will not be
		//able to do any upgrade either (since the base image is downloaded
		//to vault as well).
		//Hence, we do it in two-steps:
		//First clone the existing key(not sealed), and make it a sealed key.
		//In a subsequent release, rotate the sealed key to a new one.
		//Upgrade path will be to first upgrade to a) first release and then b)
		key, err := readDiskKey()
		if err != nil {
			return nil, fmt.Errorf("retrieving the legacy disk key from TPM failed: %w", err)
		}

		log.Noticef("try to convert the legacy key into a sealed key")

		err = SealDiskKey(log, key, DiskKeySealingPCRs)
		if err != nil {
			return nil, fmt.Errorf("sealing the legacy disk key into TPM failed: %w", err)
		}
	}
	//sealedKeyPresent && !legacyKeyPresent : unseal
	//sealedKeyPresent && legacyKeyPresent  : unseal
	if sealedKeyPresent {
		log.Noticef("sealed disk key present int TPM, about to unseal it")
	}
	//By this, we have a key sealed into TPM
	key, err := UnsealDiskKey(DiskKeySealingPCRs)
	if err == nil {
		// be more verbose, lets celebrate
		log.Noticef("successfully unsealed the disk key from TPM")
	}

	return key, err
}

// SealDiskKey seals key into TPM2.0, with provided PCRs
func SealDiskKey(log *base.LogObject, key []byte, pcrSel tpm2.PCRSelection) error {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()

	tpm2.NVUndefineSpace(rw, EmptyPassword,
		tpm2.HandleOwner, TpmSealedDiskPubHdl)

	tpm2.NVUndefineSpace(rw, EmptyPassword,
		tpm2.HandleOwner, TpmSealedDiskPrivHdl)

	//Note on any abrupt power failure at this point, and the result of it
	//We should be ok, since the key supplied here can be
	//a)
	//  FetchSealedDiskKey(), which will again supply either same value
	//  (if cloning it from non-sealed copy) or generate a new random value(fresh install)
	//  both are ok, since we are yet to setup the vault in both the cases
	//
	//or b)
	//  key received from Controller post attestation, in which case, we will
	//  again get the same key back post-reboot as well

	session, policy, err := PolicyPCRSession(rw, pcrSel)
	if err != nil {
		return fmt.Errorf("PolicyPCRSession failed: %w", err)
	}

	//Don't need the handle, we need only the policy for sealing
	if err := tpm2.FlushContext(rw, session); err != nil {
		return fmt.Errorf("flushing session handle %v failed: %w", session, err)
	}

	priv, public, err := tpm2.Seal(rw, TpmSRKHdl, EmptyPassword, EmptyPassword, policy, key)
	if err != nil {
		return fmt.Errorf("sealing the disk key into TPM failed: %w", err)
	}

	// Define space in NV storage and clean up afterwards or subsequent runs will fail.
	if err := tpm2.NVDefineSpace(rw,
		tpm2.HandleOwner,
		TpmSealedDiskPrivHdl,
		EmptyPassword,
		EmptyPassword,
		nil,
		tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead,
		uint16(len(priv)),
	); err != nil {
		return fmt.Errorf("NVDefineSpace %v failed: %w", TpmSealedDiskPrivHdl, err)
	}

	// Write the private data
	if err := tpm2.NVWrite(rw, tpm2.HandleOwner, TpmSealedDiskPrivHdl,
		EmptyPassword, priv, 0); err != nil {
		return fmt.Errorf("NVWrite %v failed: %w", TpmSealedDiskPrivHdl, err)
	}

	// Define space in NV storage
	if err := tpm2.NVDefineSpace(rw,
		tpm2.HandleOwner,
		TpmSealedDiskPubHdl,
		EmptyPassword,
		EmptyPassword,
		nil,
		tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead,
		uint16(len(public)),
	); err != nil {
		return fmt.Errorf("NVDefineSpace %v failed: %w", TpmSealedDiskPubHdl, err)
	}
	// Write the public data
	if err := tpm2.NVWrite(rw, tpm2.HandleOwner, TpmSealedDiskPubHdl,
		EmptyPassword, public, 0); err != nil {
		return fmt.Errorf("NVWrite %v failed: %w", TpmSealedDiskPubHdl, err)
	}

	// save a snapshot of current PCR values
	if err := saveDiskKeySealingPCRs(); err != nil {
		log.Warnf("saving snapshot of sealing PCRs failed: %s", err)
	}

	// In order to not lose the ability to diff and diagnose the issue,
	// first backup the previous pair of logs (if any). This is needed because
	// once the failing devices get connected to the controller to fetch the
	// backup key, we end up here again and it'll override the MeasurementLogSealSuccess
	// file content with current tpm measurement logs (which is same as the
	// content of MeasurementLogSealFail).
	if err := backupCopiedMeasurementLogs(); err != nil {
		log.Warnf("copying previous snapshot of TPM event log failed: %s", err)
	}

	// fresh start, remove old copies of measurement logs.
	removeCopiedMeasurementLogs()

	// save a copy of the current measurement log, this is also called
	// if unseal fails to have copy when we fail to unlock the vault.
	if err := copyMeasurementLog(measurementLogSealSuccess); err != nil {
		log.Warnf("copying current TPM measurement log failed: %s", err)
	}

	return nil
}

func isSealedKeyPresent() bool {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return false
	}
	defer rw.Close()

	_, err = tpm2.NVReadEx(rw, TpmSealedDiskPrivHdl,
		tpm2.HandleOwner, EmptyPassword, 0)
	return err == nil
}

func isLegacyKeyPresent() bool {
	_, err := readDiskKey()
	return err == nil
}

// UnsealDiskKey unseals key from TPM2.0
func UnsealDiskKey(pcrSel tpm2.PCRSelection) ([]byte, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	// Read all of the data with NVReadEx
	priv, err := tpm2.NVReadEx(rw, TpmSealedDiskPrivHdl,
		tpm2.HandleOwner, EmptyPassword, 0)
	if err != nil {
		return nil, fmt.Errorf("NVReadEx %v failed: %w", TpmSealedDiskPrivHdl, err)
	}
	// Read all of the data with NVReadEx
	pub, err := tpm2.NVReadEx(rw, TpmSealedDiskPubHdl,
		tpm2.HandleOwner, EmptyPassword, 0)
	if err != nil {
		return nil, fmt.Errorf("NVReadEx %v failed: %w", TpmSealedDiskPubHdl, err)
	}

	sealedObjHandle, _, err := tpm2.Load(rw, TpmSRKHdl, "", pub, priv)
	if err != nil {
		return nil, fmt.Errorf("loading the disk key into TPM failed: %w", err)
	}
	defer tpm2.FlushContext(rw, sealedObjHandle)

	session, _, err := PolicyPCRSession(rw, pcrSel)
	if err != nil {
		return nil, fmt.Errorf("PolicyPCRSession failed: %w", err)
	}
	defer tpm2.FlushContext(rw, session)

	key, err := tpm2.UnsealWithSession(rw, session, sealedObjHandle, EmptyPassword)
	if err != nil {
		// We get here mostly because of RCPolicyFail error, so first try to save
		// a copy of TPM measurement log, it comes handy for diagnosing the issue.
		evtLogStat := "copied (failed unseal) TPM measurement log"
		if errEvtLog := copyMeasurementLog(measurementLogUnsealFail); errEvtLog != nil {
			// just report the failure, still give findMismatchingPCRs a chance so
			// we can at least have some partial information about why unseal failed.
			evtLogStat = fmt.Sprintf("copying (failed unseal) TPM measurement log failed: %v", errEvtLog)
		}

		// try to find out the mismatching PCR index
		mismatch, errPcrMiss := findMismatchingPCRs()
		if errPcrMiss != nil {
			return nil, fmt.Errorf("UnsealWithSession failed: %w, %s, finding mismatching PCR failed: %v", err, evtLogStat, errPcrMiss)
		}

		return nil, fmt.Errorf("UnsealWithSession failed: %w, %s, possibly mismatching PCR indexes: %v", err, evtLogStat, mismatch)
	}
	return key, nil
}

// PolicyPCRSession prepares TPM2 Auth Policy session, with PCR as the policy
func PolicyPCRSession(rw io.ReadWriteCloser, pcrSel tpm2.PCRSelection) (tpmutil.Handle, []byte, error) {
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
		return tpm2.HandleNull, nil, fmt.Errorf("StartAuthSession failed: %w", err)
	}
	defer func() {
		if session != tpm2.HandleNull && err != nil {
			tpm2.FlushContext(rw, session)
		}
	}()

	if err = tpm2.PolicyPCR(rw, session, nil, pcrSel); err != nil {
		return session, nil, fmt.Errorf("PolicyPCR failed: %w", err)
	}

	policy, err := tpm2.PolicyGetDigest(rw, session)
	if err != nil {
		return session, nil, fmt.Errorf("PolicyGetDigest failed: %w", err)
	}
	return session, policy, nil
}

// CompareLegacyandSealedKey compares legacy and sealed keys
// to record if we are using a new key for sealed vault
func CompareLegacyandSealedKey() SealedKeyType {
	if !isSealedKeyPresent() {
		return SealedKeyTypeUnprotected
	}
	legacyKey, err := readDiskKey()
	if err != nil {
		//no cloning case, return SealedKeyTypeNew
		return SealedKeyTypeNew
	}
	unsealedKey, err := UnsealDiskKey(DiskKeySealingPCRs)
	if err != nil {
		//key is present but can't unseal it
		//but legacy key is present
		//at this point, vault is probably locked up
		return SealedKeyTypeUnknown
	}
	if bytes.Equal(legacyKey, unsealedKey) {
		//Same, return SealedKeyTypeReused
		return SealedKeyTypeReused
	}
	return SealedKeyTypeNew
}

// WipeOutStaleSealedKeyIfAny checks and deletes
// sealed vault key
func WipeOutStaleSealedKeyIfAny() error {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()

	tpm2.NVUndefineSpace(rw, EmptyPassword,
		tpm2.HandleOwner, TpmSealedDiskPubHdl)

	tpm2.NVUndefineSpace(rw, EmptyPassword,
		tpm2.HandleOwner, TpmSealedDiskPrivHdl)

	return nil
}

// PCRBankSHA256Enabled checks if SHA256 PCR Bank is
// enabled
func PCRBankSHA256Enabled() bool {
	//Check if we have cached it already, if not fetch, store and return
	if pcrBank256Status == PCRBank256StatusUnknown {
		if pcrBankSHA256EnabledHelper() {
			pcrBank256Status = PCRBank256StatusSupported
		} else {
			pcrBank256Status = PCRBank256StatusNotSupported
		}
	}
	return pcrBank256Status == PCRBank256StatusSupported
}

func pcrBankSHA256EnabledHelper() bool {
	//Fetch, cache and return
	if !IsTpmEnabled() {
		return false
	}

	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return false
	}
	defer rw.Close()

	//test is by reading PCR index 0 from SHA256 bank
	_, err = tpm2.ReadPCR(rw, 0, tpm2.AlgSHA256)
	return err == nil
}

func backupCopiedMeasurementLogs() error {
	sealSuccessBackupPath := fmt.Sprintf("%s-backup", measurementLogSealSuccess)
	unsealFailBackupPath := fmt.Sprintf("%s-backup", measurementLogUnsealFail)

	if fileutils.FileExists(nil, measurementLogSealSuccess) {
		if err := os.Rename(measurementLogSealSuccess, sealSuccessBackupPath); err != nil {
			return fmt.Errorf("failed to backup tpm \"seal success event\" previously copied measurement log: %w", err)
		}
	}

	if fileutils.FileExists(nil, measurementLogUnsealFail) {
		if err := os.Rename(measurementLogUnsealFail, unsealFailBackupPath); err != nil {
			_ = os.Rename(sealSuccessBackupPath, measurementLogSealSuccess)
			return fmt.Errorf("failed to backup tpm \"unseal fail event\" previously copied measurement log: %w", err)
		}
	}

	return nil
}

func removeCopiedMeasurementLogs() {
	os.Remove(measurementLogSealSuccess)
	os.Remove(measurementLogUnsealFail)
}

func copyMeasurementLog(dstPath string) error {
	var appendErr error
	tpmEventLog, err := os.ReadFile(measurementLogFile)
	if err != nil {
		return fmt.Errorf("failed to read TPM measurements log file: %w", err)
	}

	measurefsEventLog, err := os.ReadFile(measurefsTpmEventLog)
	if err == nil {
		// append the measurefs event log to the tpm event log
		tpmEventLog = append(tpmEventLog, measurefsEventLog...)
	} else {
		// don't fail yet, we might still be able to copy tpm event logs
		appendErr = fmt.Errorf("failed to read measure-config measurements log file: %w", err)
	}

	err = fileutils.WriteRename(dstPath, tpmEventLog)
	if err != nil {
		if appendErr != nil {
			return fmt.Errorf("failed to copy tpm and measurefs event logs: %w, %v", err, appendErr)
		}

		return fmt.Errorf("failed to copy tpm measurement log data: %w", err)
	}

	return nil
}

func saveDiskKeySealingPCRs() error {
	trw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return err
	}
	defer trw.Close()

	readPCRs, err := readDiskKeySealingPCRs()
	if err != nil {
		return err
	}

	buff := new(bytes.Buffer)
	e := gob.NewEncoder(buff)
	err = e.Encode(readPCRs)
	if err != nil {
		return err
	}

	return fileutils.WriteRename(savedSealingPcrsFile, buff.Bytes())
}

func findMismatchingPCRs() ([]int, error) {
	frw, err := os.Open(savedSealingPcrsFile)
	if err != nil {
		return nil, err
	}
	defer frw.Close()

	var savedPCRs map[int][]byte
	d := gob.NewDecoder(frw)
	err = d.Decode(&savedPCRs)
	if err != nil {
		return nil, err
	}

	readPCRs, err := readDiskKeySealingPCRs()
	if err != nil {
		return nil, err
	}

	mismatch := make([]int, 0)
	for i, savedPCR := range savedPCRs {
		readPCR, ok := readPCRs[i]
		// this should never happen, except when we update EVE and adding new
		// indexes to the DiskKeySealingPCRs, anyways, better safe than sorry!
		if !ok {
			return nil, fmt.Errorf("saved PCR index %d doesn't exist at run-time PCRs list %v", i, DiskKeySealingPCRs.PCRs)
		}

		if !bytes.Equal(readPCR, savedPCR) {
			mismatch = append(mismatch, i)
		}
	}

	sort.Ints(mismatch)
	return mismatch, nil
}

func readDiskKeySealingPCRs() (map[int][]byte, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	// tpm2.ReadPCRs returns at most 8 PCRs, so loop over and read one by one
	readPCRs := make(map[int][]byte)
	for _, v := range DiskKeySealingPCRs.PCRs {
		p, err := tpm2.ReadPCR(rw, v, DiskKeySealingPCRs.Hash)
		if err != nil {
			return nil, err
		}

		readPCRs[v] = p
	}

	return readPCRs, nil
}
