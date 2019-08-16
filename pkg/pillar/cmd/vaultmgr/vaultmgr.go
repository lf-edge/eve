// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vaultmgr

import (
	"bytes"
	"errors"
	"flag"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cmd/tpmmgr"
	log "github.com/sirupsen/logrus"
)

const (
	fscryptPath     = "/opt/zededa/bin/fscrypt"
	keyctlPath      = "/bin/keyctl"
	mountPoint      = "/persist/"
	vaultPath       = "/persist/vault"
	keyDir          = "/TmpVaultDir"
	protectorName   = "TheVaultProtector"
	vaultKeyLen     = 32 //bytes
	vaultHalfKeyLen = 16 //bytes
)

var (
	keyFile        = keyDir + "/protector.key"
	keyctlParams   = []string{"link", "@u", "@s"}
	mntPointParams = []string{"setup", mountPoint, "--quiet"}
	statusParams   = []string{"status", mountPoint}
	setupParams    = []string{"setup", "--quiet"}
	encryptParams  = []string{"encrypt", vaultPath, "--key=" + keyFile,
		"--source=raw_key", "--name=" + protectorName,
		"--user=root"}
	unlockParams = []string{"unlock", vaultPath, "--key=" + keyFile,
		"--user=root"}
)

//Error values
var (
	ErrNoTpm       = errors.New("No TPM on this system")
	ErrInvalKeyLen = errors.New("Unexpected key length")
)

func execCmd(command string, args ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer

	cmd := exec.Command(command, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	stdoutStr, stderrStr := stdout.String(), stderr.String()
	return stdoutStr, stderrStr, err
}

func linkKeyrings() error {
	if _, _, err := execCmd(keyctlPath, keyctlParams...); err != nil {
		log.Fatalf("Error in linking user keyring %v", err)
		return err
	}
	return nil
}

func retrieveTpmKey() ([]byte, error) {
	var tpmKey []byte
	var err error
	if tpmmgr.IsTpmEnabled() {
		tpmKey, err = tpmmgr.FetchVaultKey()
		if err != nil {
			log.Errorf("Error fetching TPM key: %v", err)
			return nil, err
		}
		return tpmKey, nil
	} else {
		return nil, ErrNoTpm
	}
}

func retrieveCloudKey() ([]byte, error) {
	//For now, return a dummy key, until controller support is ready.
	cloudKey := []byte("foobarfoobarfoobarfoobarfoobarfo")
	return cloudKey, nil
}

func mergeKeys(key1 []byte, key2 []byte) ([]byte, error) {
	if len(key1) != vaultKeyLen ||
		len(key2) != vaultKeyLen {
		return nil, ErrInvalKeyLen
	}

	//merge first half of key1 with second half of key2
	v1 := vaultHalfKeyLen
	v2 := vaultKeyLen
	mergedKey := []byte("")
	mergedKey = append(mergedKey, key1[0:v1]...)
	mergedKey = append(mergedKey, key2[v1:v2]...)
	return mergedKey, nil
}

func deriveVaultKey() ([]byte, error) {
	//First fetch Cloud Key
	cloudKey, err := retrieveCloudKey()
	if err != nil {
		return nil, err
	}

	//Next fetch TPM key, if one is available
	tpmKey, err := retrieveTpmKey()
	if err == ErrNoTpm {
		return cloudKey, nil
	} else if err == nil {
		return mergeKeys(tpmKey, cloudKey)
	} else {
		//TPM is present but still error retriving the key
		return nil, err
	}
}

//stageKey is responsible for talking to TPM and Controller
//and preparing the key for accessing the vault
func stageKey() error {
	//Create a tmpfs file to pass the secret to fscrypt
	if _, _, err := execCmd("mkdir", keyDir); err != nil {
		log.Fatalf("Error creating keyDir %v", err)
		return err
	}

	if _, _, err := execCmd("mount", "-t", "tmpfs", "tmpfs", keyDir); err != nil {
		log.Fatalf("Error mounting tmpfs on keyDir: %v", err)
		return err
	}

	vaultKey, err := deriveVaultKey()
	if err != nil {
		log.Errorf("Error deriving key for accessing the vault: %v", err)
		return err
	}
	if err := ioutil.WriteFile(keyFile, vaultKey, 0700); err != nil {
		log.Fatalf("Error creating keyFile: %v", err)
	}
	return nil
}

func unstageKey() {
	//Shred the tmpfs file, and remove it
	if _, _, err := execCmd("shred", "--remove", keyFile); err != nil {
		log.Fatalf("Error shredding keyFile: %v", err)
		return
	}
	if _, _, err := execCmd("umount", keyDir); err != nil {
		log.Fatalf("Error unmounting: %v", err)
		return
	}
	if _, _, err := execCmd("rm", "-rf", keyDir); err != nil {
		log.Fatalf("Error removing keyDir: %v", err)
		return
	}
	return
}

//handleFirstUse sets up vault for the first time use
func handleFirstUse() error {
	//setup mountPoint for encryption
	if _, _, err := execCmd(fscryptPath, mntPointParams...); err != nil {
		log.Fatalf("Error setting up mountpoint for encrption: %v", err)
		return err
	}

	//Create vault
	if _, _, err := execCmd("mkdir", vaultPath); err != nil {
		log.Fatalf("Error creating vault: %v", err)
		return err
	}

	if err := stageKey(); err != nil {
		return err
	}
	defer unstageKey()

	//Encrypt vault, and unlock it for accessing
	if _, _, err := execCmd(fscryptPath, encryptParams...); err != nil {
		log.Errorf("Encryption failed: %v", err)
		return err
	}

	return linkKeyrings()
}

func unlockVault() error {
	if err := stageKey(); err != nil {
		return err
	}
	defer unstageKey()

	//Unlock vault for access
	if _, _, err := execCmd(fscryptPath, unlockParams...); err != nil {
		log.Fatalf("Error unlocking vault: %v", err)
		return err
	}
	return linkKeyrings()
}

func setupVault() error {
	//setup fscrypt.conf, if not done already
	if _, _, err := execCmd(fscryptPath, setupParams...); err != nil {
		log.Fatalf("Error setting up fscrypt.conf: %v", err)
		return err
	}
	//Check if /persist is already setup for encryption
	if _, _, err := execCmd(fscryptPath, statusParams...); err != nil {
		//Not yet setup, set it up for the first use
		return handleFirstUse()
	}
	//Already setup for encryption, go for unlocking
	return unlockVault()
}

//Run is the entrypoint for running vaultmgr as a standalone program
func Run() {

	curpartPtr := flag.String("c", "", "Current partition")
	flag.Parse()

	curpart := *curpartPtr

	log.SetLevel(log.DebugLevel)

	// Sending json log format to stdout
	logf, err := agentlog.Init("vaultmgr", curpart)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	switch flag.Args()[0] {
	case "setupVault":
		if err = setupVault(); err != nil {
			log.Fatal("Error in setting up vault:", err)
			os.Exit(1)
		}
	default:
		log.Errorln("Unknown Argument")
		os.Exit(1)
	}
}
