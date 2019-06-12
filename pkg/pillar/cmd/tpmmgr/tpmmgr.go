// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package tpmmgr

import (
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"time"
)

const (
	//TpmPubKeyName is the file to store TPM public key file
	TpmPubKeyName = "/var/tmp/tpm.eccpubk.der"

	//TpmDeviceCertFileName is the file name to store device certificate
	TpmDeviceCertFileName = "/config/device.cert.pem"

	//TpmDevicePath is the TPM device file path
	TpmDevicePath = "/dev/tpm0"

	//TpmEnabledFile is the file to indicate if TPM is being used by SW
	TpmEnabledFile = "/persist/config/tpm_in_use"

	//TpmDeviceKeyHdl is the well known TPM permanent handle for device key
	TpmDeviceKeyHdl tpmutil.Handle = 0x817FFFFF

	//TpmDeviceCertHdl is the well known TPM NVIndex for device cert
	TpmDeviceCertHdl tpmutil.Handle = 0x1500000

	//TpmPasswdHdl is the well known TPM NVIndex for TPM Credentials
	TpmPasswdHdl tpmutil.Handle = 0x1600000

	tpmCredentialsFileName = "/config/tpm_credential"
	emptyPassword          = ""
	tpmLockName            = "/var/tmp/zededa/tpm.lock"
	maxPasswdLength        = 7 //limit TPM password to this length
)

var (
	pcrSelection     = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{7}}
	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagNoDA |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpm2.AlgSHA256,
			},
			CurveID: tpm2.CurveNISTP256,
			Point:   tpm2.ECPoint{X: big.NewInt(0), Y: big.NewInt(0)},
		},
	}
)

func createDeviceKey() error {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		log.Errorln(err)
		return err
	}
	defer rw.Close()

	tpmOwnerPasswdBytes, err := ioutil.ReadFile(tpmCredentialsFileName)
	if err != nil {
		log.Fatalf("Reading from %s failed: %s", tpmCredentialsFileName, err)
		return err
	}

	tpmOwnerPasswd := string(tpmOwnerPasswdBytes)
	if len(tpmOwnerPasswd) > maxPasswdLength {
		tpmOwnerPasswd = tpmOwnerPasswd[0:maxPasswdLength]
	}

	//No previous key, create new one
	signerHandle, newPubKey, err := tpm2.CreatePrimary(rw,
		tpm2.HandleOwner,
		pcrSelection,
		emptyPassword,
		tpmOwnerPasswd,
		defaultKeyParams)
	if err != nil {
		log.Errorf("CreatePrimary failed: %s, do BIOS reset of TPM", err)
		return err
	}
	if err := tpm2.EvictControl(rw, emptyPassword,
		tpm2.HandleOwner,
		TpmDeviceKeyHdl,
		TpmDeviceKeyHdl); err != nil {
		log.Errorf("EvictControl failed: %v", err)
	}
	if err := tpm2.EvictControl(rw, emptyPassword,
		tpm2.HandleOwner, signerHandle,
		TpmDeviceKeyHdl); err != nil {
		log.Errorf("EvictControl failed: %v, do BIOS reset of TPM", err)
		return err
	}

	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(newPubKey)
	err = ioutil.WriteFile(TpmPubKeyName, pubKeyBytes, 0644)
	if err != nil {
		log.Errorf("Error in writing TPM public key to file: %v", err)
		return err
	}

	return nil
}

func lockTpmAccess() {
	for os.Mkdir(tpmLockName, 0750) != nil {
		log.Debugln("Waiting for TPM lock.")
		time.Sleep(1000 * time.Millisecond)
	}
	//XXX check if this sleep is still required
	time.Sleep(1000 * time.Millisecond)
}

func unlockTpmAccess() {
	os.Remove(tpmLockName)
}

//TpmSign is used by external packages to get a digest signed by
//device key in TPM
func TpmSign(digest []byte) (*big.Int, *big.Int, error) {
	lockTpmAccess()
	defer unlockTpmAccess()

	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return nil, nil, err
	}
	defer rw.Close()

	tpmOwnerPasswdBytes, err := ioutil.ReadFile(tpmCredentialsFileName)
	if err != nil {
		log.Fatalf("Reading from %s failed: %s", tpmCredentialsFileName, err)
		return nil, nil, err
	}
	tpmOwnerPasswd := string(tpmOwnerPasswdBytes)
	if len(tpmOwnerPasswd) > maxPasswdLength {
		tpmOwnerPasswd = tpmOwnerPasswd[0:maxPasswdLength]
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
		tpmOwnerPasswd, digest, scheme)
	if err != nil {
		log.Errorln("Sign using TPM failed")
		return nil, nil, err
	}
	return sig.ECC.R, sig.ECC.S, nil
}

func writeDeviceCert() error {
	lockTpmAccess()
	defer unlockTpmAccess()

	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()

	if err := tpm2.NVUndefineSpace(rw, emptyPassword,
		tpm2.HandleOwner, TpmDeviceCertHdl,
	); err != nil {
		log.Debugf("NVUndefineSpace failed: %v", err)
	}

	deviceCertBytes, err := ioutil.ReadFile(TpmDeviceCertFileName)
	if err != nil {
		log.Errorf("Failed to read device cert file: %v", err)
		return err
	}

	// Define space in NV storage and clean up afterwards or subsequent runs will fail.
	if err := tpm2.NVDefineSpace(rw,
		tpm2.HandleOwner,
		TpmDeviceCertHdl,
		emptyPassword,
		emptyPassword,
		nil,
		tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead,
		uint16(len(deviceCertBytes)),
	); err != nil {
		log.Errorf("NVDefineSpace failed: %v", err)
		return err
	}

	// Write the data
	if err := tpm2.NVWrite(rw, tpm2.HandleOwner, TpmDeviceCertHdl,
		emptyPassword, deviceCertBytes, 0); err != nil {
		log.Errorf("NVWrite failed: %v", err)
		return err
	}
	return nil
}

func readDeviceCert() error {
	lockTpmAccess()
	defer unlockTpmAccess()

	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()

	// Read all of the data with NVReadEx
	deviceCertBytes, err := tpm2.NVReadEx(rw, TpmDeviceCertHdl,
		tpm2.HandleOwner, emptyPassword, 0)
	if err != nil {
		log.Errorf("NVReadEx failed: %v", err)
		return err
	}

	err = ioutil.WriteFile(TpmDeviceCertFileName, deviceCertBytes, 0644)
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
		// Generate a new uuid
		out, err := exec.Command("uuidgen").Output()
		if err != nil {
			log.Fatalf("Error in generating uuid, %v", err)
			return err
		}
		//Write uuid to credentials file for faster access
		err = ioutil.WriteFile(tpmCredentialsFileName, out, 0644)
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
	lockTpmAccess()
	defer unlockTpmAccess()

	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()

	if err := tpm2.NVUndefineSpace(rw, emptyPassword,
		tpm2.HandleOwner, TpmPasswdHdl,
	); err != nil {
		log.Debugf("NVUndefineSpace failed: %v", err)
	}

	tpmCredentialBytes, err := ioutil.ReadFile(tpmCredentialsFileName)
	if err != nil {
		log.Errorf("Failed to read credentials file: %v", err)
		return err
	}

	// Define space in NV storage and clean up afterwards or subsequent runs will fail.
	if err := tpm2.NVDefineSpace(rw,
		tpm2.HandleOwner,
		TpmPasswdHdl,
		emptyPassword,
		emptyPassword,
		nil,
		tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead,
		uint16(len(tpmCredentialBytes)),
	); err != nil {
		log.Errorf("NVDefineSpace failed: %v", err)
		return err
	}

	// Write the data
	if err := tpm2.NVWrite(rw, tpm2.HandleOwner, TpmPasswdHdl,
		emptyPassword, tpmCredentialBytes, 0); err != nil {
		log.Errorf("NVWrite failed: %v", err)
		return err
	}
	return nil
}

func readCredentials() error {
	lockTpmAccess()
	defer unlockTpmAccess()

	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()

	// Read all of the data with NVReadEx
	tpmCredentialBytes, err := tpm2.NVReadEx(rw, TpmPasswdHdl,
		tpm2.HandleOwner, emptyPassword, 0)
	if err != nil {
		log.Errorf("NVReadEx failed: %v", err)
		return err
	}

	err = ioutil.WriteFile(tpmCredentialsFileName, tpmCredentialBytes, 0644)
	if err != nil {
		log.Errorf("Writing to credentials file failed: %v", err)
		return err
	}

	return nil
}

func printCapability() error {
	lockTpmAccess()
	defer unlockTpmAccess()

	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return err
	}
	defer rw.Close()
	l, _, err := tpm2.GetCapability(rw, tpm2.CapabilityTPMProperties,
		1, uint32(0x105))
	fmt.Println(l)
	return err
}

func Run() {
	curpartPtr := flag.String("c", "", "Current partition")
	flag.Parse()

	curpart := *curpartPtr

	log.SetLevel(log.DebugLevel)

	// Sending json log format to stdout
	logf, err := agentlog.Init("tpmmgr", curpart)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	switch os.Args[1] {
	case "genKey":
		if err = createDeviceKey(); err != nil {
			log.Fatal("Error in creating primary key, ", err)
			os.Exit(1)
		}
	case "readDeviceCert":
		if err = readDeviceCert(); err != nil {
			log.Errorln("Error in reading device cert")
			os.Exit(1)
		}
	case "writeDeviceCert":
		if err = writeDeviceCert(); err != nil {
			log.Errorln("Error in writing device cert")
			os.Exit(1)
		}
	case "readCredentials":
		if err = readCredentials(); err != nil {
			log.Errorln("Error in reading credentials")
			os.Exit(1)
		}
	case "genCredentials":
		if err = genCredentials(); err != nil {
			log.Errorln("Error in generating credentials")
			os.Exit(1)
		}
	case "printCapability":
		if err = printCapability(); err != nil {
			log.Errorln("Error in fetching capability")
			os.Exit(1)
		}
	}
}
