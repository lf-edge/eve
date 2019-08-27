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
	"path/filepath"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cmd/tpmmgr"
	log "github.com/sirupsen/logrus"
)

const (
	fscryptPath     = "/opt/zededa/bin/fscrypt"
	keyctlPath      = "/bin/keyctl"
	mountPoint      = "/persist/"
	defaultImgVault = "/persist/img"
	defaultCfgVault = "/persist/config"
	keyDir          = "/TmpVaultDir"
	protectorPrefix = "TheVaultKey"
	vaultKeyLen     = 32 //bytes
	vaultHalfKeyLen = 16 //bytes
)

var (
	keyFile           = keyDir + "/protector.key"
	keyctlParams      = []string{"link", "@u", "@s"}
	mntPointParams    = []string{"setup", mountPoint, "--quiet"}
	statusParams      = []string{"status", mountPoint}
	vaultStatusParams = []string{"status"}
	setupParams       = []string{"setup", "--quiet"}
)

func getEncryptParams(vaultPath string) []string {
	args := []string{"encrypt", vaultPath, "--key=" + keyFile,
		"--source=raw_key", "--name=" + protectorPrefix + filepath.Base(vaultPath),
		"--user=root"}
	return args
}

func getUnlockParams(vaultPath string) []string {
	args := []string{"unlock", vaultPath, "--key=" + keyFile,
		"--user=root"}
	return args
}

func getStatusParams(vaultPath string) []string {
	args := vaultStatusParams
	return append(args, vaultPath)
}

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

func isDirEmpty(path string) bool {
	if f, err := os.Open(path); err == nil {
		files, err := f.Readdirnames(0)
		if err != nil {
			log.Errorf("Error reading dir contents: %v", err)
			return false
		}
		if len(files) == 0 {
			log.Debugf("No files in %s", path)
			return true
		}
		if len(files) == 1 && files[0] == "lost+found" {
			log.Debugf("Ignoring lost+found on %s", path)
			execCmd("rm", "-rf", path+"/lost+found")
			return true
		}
	}
	log.Debugf("Dir is not empty at %s", path)
	return false
}

//handleFirstUse sets up mountpoint for the first time use
func handleFirstUse() error {
	//setup mountPoint for encryption
	if _, _, err := execCmd(fscryptPath, mntPointParams...); err != nil {
		log.Fatalf("Error setting up mountpoint for encrption: %v", err)
		return err
	}
	return nil
}

func unlockVault(vaultPath string) error {
	if err := stageKey(); err != nil {
		return err
	}
	defer unstageKey()

	//Unlock vault for access
	if _, _, err := execCmd(fscryptPath, getUnlockParams(vaultPath)...); err != nil {
		log.Fatalf("Error unlocking vault: %v", err)
		return err
	}
	return linkKeyrings()
}

//createVault expects an empty, existing dir at vaultPath
func createVault(vaultPath string) error {
	if err := stageKey(); err != nil {
		return err
	}
	defer unstageKey()

	//Encrypt vault, and unlock it for accessing
	if stdout, stderr, err := execCmd(fscryptPath, getEncryptParams(vaultPath)...); err != nil {
		log.Errorf("Encryption failed: %v, %s, %s", err, stdout, stderr)
		return err
	}
	return linkKeyrings()
}

func setupVault(vaultPath string) error {
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		//Create vault dir
		if _, _, err := execCmd("mkdir", "-p", vaultPath); err != nil {
			return err
		}
	}
	args := getStatusParams(vaultPath)
	if _, _, err := execCmd(fscryptPath, args...); err != nil {
		if !isDirEmpty(vaultPath) {
			//Don't disturb existing installations
			log.Debugf("Not disturbing non-empty %s", vaultPath)
			return nil
		}
		return createVault(vaultPath)
	}
	//Already setup for encryption, go for unlocking
	log.Debugf("Unlocking %s", vaultPath)
	return unlockVault(vaultPath)
}

func setupFscryptEnv() error {
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
	return nil
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
	case "setupVaults":
		if err = setupFscryptEnv(); err != nil {
			log.Fatal("Error in setting up fscrypt environment:", err)
		}
		if err = setupVault(defaultImgVault); err != nil {
			log.Fatalf("Error in setting up vault %s:%v", defaultImgVault, err)
		}
		if err = setupVault(defaultCfgVault); err != nil {
			log.Fatalf("Error in setting up vault %s %v", defaultImgVault, err)
		}
	default:
		log.Errorln("Unknown Argument")
		os.Exit(1)
	}
}
