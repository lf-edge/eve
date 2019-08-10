// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vaultmgr

import (
	"bytes"
	"flag"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cmd/tpmmgr"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"os/exec"
)

const (
	fscryptPath   = "/opt/zededa/bin/fscrypt"
	keyctlPath    = "/bin/keyctl"
	mountPoint    = "/persist/"
	vaultPath     = "/persist/vault"
	keyDir        = "/TmpVaultDir"
	protectorName = "TheVaultProtector"
	vaultKeyLen   = 32 //bytes
)

var (
	keyFile        = keyDir + "/protector.key"
	keyctlParams   = []string{"link", "@u", "@s"}
	gblSetupParams = []string{"setup", "--quiet"}
	mntPointParams = []string{"setup", mountPoint, "--quiet"}
	statusParams   = []string{"status", mountPoint}
	setupParams    = []string{"setup", "--quiet"}
	encryptParams  = []string{"encrypt", vaultPath, "--key=" + keyFile,
		"--source=raw_key", "--name=" + protectorName,
		"--user=root"}
	unlockParams = []string{"unlock", vaultPath, "--key=" + keyFile,
		"--user=root"}
)

func execCmd(command string, args ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer

	cmd := exec.Command(command, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	stdoutStr, stderrStr := string(stdout.Bytes()), string(stderr.Bytes())
	return stdoutStr, stderrStr, err
}

func linkKeyrings() error {
	if _, _, err := execCmd(keyctlPath, keyctlParams...); err != nil {
		log.Fatalf("Error in linking user keyring %v", err)
		return err
	}
	return nil
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

	//XXX: This section will change once Controller integration is complete.
	//XXX: For now assumes only TPM part of the key logic
	var tpmKey []byte
	var err error
	if tpmmgr.IsTpmEnabled() {
		tpmKey, err = tpmmgr.FetchVaultKey()
		if err != nil {
			log.Fatalf("Error fetching TPM key: %v", err)
			return err
		}
	} else {
		//No TPM on this device.
		tpmKey = make([]byte, vaultKeyLen)
	}

	if err := ioutil.WriteFile(keyFile, tpmKey, 0700); err != nil {
		log.Fatalf("Error creating keyFile: %v", err)
	}
	return nil
}

func unstageKey() error {
	//Shred the tmpfs file, and remove it
	if _, _, err := execCmd("shred", "--remove", keyFile); err != nil {
		log.Fatalf("Error shredding keyFile: %v", err)
		return err
	}
	if _, _, err := execCmd("umount", keyDir); err != nil {
		log.Fatalf("Error unmounting: %v", err)
		return err
	}
	if _, _, err := execCmd("rm", "-rf", keyDir); err != nil {
		log.Fatalf("Error removing keyDir: %v", err)
		return err
	}
	return nil
}

//handleFirstUse sets up vault for first time use
func handleFirstUse() error {
	//setup fscrypt.conf
	if _, _, err := execCmd(fscryptPath, setupParams...); err != nil {
		log.Fatalf("Error setting up fscrypt.conf: %v", err)
		return err
	}

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
	if _, _, err := execCmd(fscryptPath, statusParams...); err != nil {
		return handleFirstUse()
	}
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

	switch os.Args[1] {
	case "setupVault":
		if err = setupVault(); err != nil {
			log.Fatal("Error in setting up vault:", err)
			os.Exit(1)
		}
	}
}
