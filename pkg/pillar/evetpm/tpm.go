// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"unsafe"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	//TpmDevicePath is the TPM device file path
	TpmDevicePath = "/dev/tpmrm0"

	//TpmPasswdHdl is the well known TPM NVIndex for TPM Credentials
	TpmPasswdHdl tpmutil.Handle = 0x1600000

	//TpmEKHdl is the well known TPM permanent handle for Endorsement key
	TpmEKHdl tpmutil.Handle = 0x81000001

	//TpmSRKHdl is the well known TPM permanent handle for Storage key
	TpmSRKHdl tpmutil.Handle = 0x81000002

	//TpmAKHdl is the well known TPM permanent handle for AIK key
	TpmAKHdl tpmutil.Handle = 0x81000003

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

	//EmptyPassword is an empty string
	EmptyPassword  = ""
	vaultKeyLength = 32 //Bytes
)

var (
	//EcdhKeyFile is the location of the ecdh private key
	//on devices without a TPM. It is not a constant due to test usage
	EcdhKeyFile = types.PersistConfigDir + "/ecdh.key.pem"

	tpmHwInfo = ""
)

//TpmPrivateKey is Custom implementation of crypto.PrivateKey interface
type TpmPrivateKey struct {
	PublicKey crypto.PublicKey
}

//Helper structure to pack ecdsa signature for ASN1 encoding
type ecdsaSignature struct {
	R, S *big.Int
}

//Public implements crypto.PrivateKey interface
func (s TpmPrivateKey) Public() crypto.PublicKey {
	clientCertBytes, err := ioutil.ReadFile(types.DeviceCertName)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(clientCertBytes)
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	ecdsaPublicKey := cert.PublicKey.(*ecdsa.PublicKey)
	return ecdsaPublicKey
}

//Sign implements cryto.PrivateKey interface
func (s TpmPrivateKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	R, S, err := TpmSign(digest)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ecdsaSignature{R, S})
}

//ReadOwnerCrdl returns credential specific to this device
func ReadOwnerCrdl() (string, error) {
	tpmOwnerPasswdBytes, err := ioutil.ReadFile(TpmCredentialsFileName)
	if err != nil {
		return "", err
	}
	tpmOwnerPasswd := string(tpmOwnerPasswdBytes)
	if len(tpmOwnerPasswd) > MaxPasswdLength {
		tpmOwnerPasswd = tpmOwnerPasswd[0:MaxPasswdLength]
	}
	return tpmOwnerPasswd, nil
}

//TpmSign is used by external packages to get a digest signed by
//device key in TPM
func TpmSign(digest []byte) (*big.Int, *big.Int, error) {

	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return nil, nil, err
	}
	defer rw.Close()

	tpmOwnerPasswd, err := ReadOwnerCrdl()
	if err != nil {
		return nil, nil, fmt.Errorf("Error in fetching TPM credentials: %v", err)
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
		return nil, nil, fmt.Errorf("Sign using TPM failed with error %v", err)
	}
	return sig.ECC.R, sig.ECC.S, nil
}

//FileExists returns true if a file with name filename is found
func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

//IsTpmEnabled checks if TPM is being used by software for creating device cert
func IsTpmEnabled() bool {
	return FileExists(types.DeviceCertName) && !FileExists(types.DeviceKeyName)
}

//GetRandom returns a random []byte of requested length
func GetRandom(numBytes uint16) ([]byte, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return nil, err
	}
	defer rw.Close()
	return tpm2.GetRandom(rw, numBytes)
}

//GetModelName combines vendor1 and vendor2 values into a string
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

//GetFirmwareVersion converts v1, v2 values from TPM properties to string
func GetFirmwareVersion(v1 uint32, v2 uint32) string {
	get16 := func(val uint32, offset uint32) uint16 {
		return uint16((val >> ((1 - offset) * 16)) & 0xFFFF)
	}
	return fmt.Sprintf("%d.%d.%d.%d", get16(v1, 0), get16(v1, 1),
		get16(v2, 0), get16(v2, 1))
}

//GetTpmProperty fetches a given property id, and returns it as uint32
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
		return 0, fmt.Errorf("Unable to fetch property %d", propID)
	}
	return prop.Value, nil
}

//FetchTpmSwStatus returns states reflecting SW usage of TPM
func FetchTpmSwStatus() info.HwSecurityModuleStatus {
	_, err := os.Stat(TpmDevicePath)
	if err != nil {
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

//Refer to https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Version-1.01-Revision-1.00.pdf
//These byte sequences in uint32 format is actually ASCII representation of TPM
//vendor ID. Since they are abbreviated names, we are having a map here to show
//a more verbose form of vendor name
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

//till we have next version of go-tpm released, use this
const (
	tpmPropertyManufacturer tpm2.TPMProp = 0x105
	tpmPropertyVendorStr1   tpm2.TPMProp = 0x106
	tpmPropertyVendorStr2   tpm2.TPMProp = 0x107
	tpmPropertyFirmVer1     tpm2.TPMProp = 0x10b
	tpmPropertyFirmVer2     tpm2.TPMProp = 0x10c
)

//FetchTpmHwInfo returns TPM Hardware properties in a string
func FetchTpmHwInfo() (string, error) {

	//If we had done this earlier, return the last result
	if tpmHwInfo != "" {
		return tpmHwInfo, nil
	}

	//Take care of non-TPM platforms
	_, err := os.Stat(TpmDevicePath)
	if err != nil {
		tpmHwInfo = "Not Available"
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

//FetchVaultKey retreives TPM part of the vault key
func FetchVaultKey(log *base.LogObject) ([]byte, error) {
	//First try to read from TPM, if it was stored earlier
	key, err := readDiskKey(log)
	if err != nil {
		key, err = GetRandom(vaultKeyLength)
		if err != nil {
			log.Errorf("Error in generating random number: %v", err)
			return nil, err
		}
		err = writeDiskKey(log, key)
		if err != nil {
			log.Errorf("Writing Disk Key to TPM failed: %v", err)
			return nil, err
		}
	}
	return key, nil
}

//SealVaultKey seals the given key against TPM PCRs
func SealVaultKey(key []byte) error {
	//XXX: fill it in with PCR Sealing code
	return nil
}

func writeDiskKey(log *base.LogObject, key []byte) error {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()

	if err := tpm2.NVUndefineSpace(rw, EmptyPassword,
		tpm2.HandleOwner, TpmDiskKeyHdl,
	); err != nil {
		log.Debugf("NVUndefineSpace failed: %v", err)
	}

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
		log.Errorf("NVDefineSpace failed: %v", err)
		return err
	}

	// Write the data
	if err := tpm2.NVWrite(rw, tpm2.HandleOwner, TpmDiskKeyHdl,
		EmptyPassword, key, 0); err != nil {
		log.Errorf("NVWrite failed: %v", err)
		return err
	}
	return nil
}

func readDiskKey(log *base.LogObject) ([]byte, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	// Read all of the data with NVReadEx
	keyBytes, err := tpm2.NVReadEx(rw, TpmDiskKeyHdl,
		tpm2.HandleOwner, EmptyPassword, 0)
	if err != nil {
		log.Errorf("NVReadEx failed: %v", err)
		return nil, err
	}
	return keyBytes, nil
}
