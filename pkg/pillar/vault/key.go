// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
)

var (
	errInvalidKeyLen = errors.New("unexpected key length")
)

const (
	vaultKeyLen = 32 //bytes
)

func retrieveTpmKey(log *base.LogObject, useSealedKey bool) ([]byte, error) {
	if useSealedKey {
		return etpm.FetchSealedVaultKey(log)
	}
	return etpm.FetchVaultKey(log)
}

// retrieveCloudKey is to support pre-5.6.2 devices, remove once devices move to 5.6.2
func retrieveCloudKey() ([]byte, error) {
	// For now, return a dummy key, until controller support is ready.
	cloudKey := []byte("foobarfoobarfoobarfoobarfoobarfo")
	return cloudKey, nil
}

// cloudKeyOnlyMode is set when the key is used only from cloud, and not from TPM.
func deriveVaultKey(log *base.LogObject, cloudKeyOnlyMode, useSealedKey, tpmKeyOnlyMode bool) ([]byte, error) {
	// First fetch Cloud Key
	cloudKey, err := retrieveCloudKey()
	if err != nil {
		return nil, err
	}
	// For pre 5.6.2 devices, remove once devices move to 5.6.2
	if cloudKeyOnlyMode {
		log.Functionf("Using cloud key")
		return cloudKey, nil
	}
	tpmKey, err := retrieveTpmKey(log, useSealedKey)
	if err != nil {
		return nil, err
	}

	if tpmKeyOnlyMode == false {
		log.Notice("Calling mergeKeys")
		return mergeKeys(log, tpmKey, cloudKey)
	}
	log.Notice("Using TPM key only")
	return tpmKey, nil
}

// stageKey is responsible for talking to TPM and Controller
// and preparing the key for accessing the vault
// returns function to unstage the key
func stageKey(log *base.LogObject, cloudKeyOnlyMode, useSealedKey, tpmKeyOnlyMode bool, keyDirName string, keyFileName string) (func(), error) {
	// Create a tmpfs file to pass the secret to fscrypt
	if err := os.MkdirAll(keyDirName, 755); err != nil {
		return nil, fmt.Errorf("error creating keyDir %s %v", keyDirName, err)
	}

	if _, _, err := execCmd("mount", "-t", "tmpfs", "tmpfs", keyDirName); err != nil {
		return nil, fmt.Errorf("error mounting tmpfs on keyDir %s: %v", keyDirName, err)
	}

	vaultKey, err := deriveVaultKey(log, cloudKeyOnlyMode, useSealedKey, tpmKeyOnlyMode)
	if err != nil {
		log.Errorf("Error deriving key for accessing the vault: %v", err)
		unstageKey(log, keyDirName, keyFileName)
		return nil, err
	}
	if err := ioutil.WriteFile(keyFileName, vaultKey, 0700); err != nil {
		unstageKey(log, keyDirName, keyFileName)
		return nil, fmt.Errorf("error creating keyFile: %v", err)
	}
	return func() { unstageKey(log, keyDirName, keyFileName) }, nil
}

func unstageKey(log *base.LogObject, keyDirName string, keyFileName string) {
	_, err := os.Stat(keyFileName)
	if !os.IsNotExist(err) {
		// Shred the tmpfs file, and remove it
		if _, _, err := execCmd("shred", "--remove", keyFileName); err != nil {
			log.Errorf("Error shredding keyFile %s: %v", keyFileName, err)
			return
		}
	}
	if _, _, err := execCmd("umount", keyDirName); err != nil {
		log.Errorf("Error unmounting %s: %v", keyDirName, err)
		return
	}
	if _, _, err := execCmd("rm", "-rf", keyDirName); err != nil {
		log.Errorf("Error removing keyDir %s : %v", keyDirName, err)
		return
	}
	return
}

func mergeKeys(log *base.LogObject, key1 []byte, key2 []byte) ([]byte, error) {
	if len(key1) != vaultKeyLen ||
		len(key2) != vaultKeyLen {
		return nil, errInvalidKeyLen
	}

	// merge first half of key1 with second half of key2
	v1 := vaultKeyLen / 2
	v2 := vaultKeyLen
	mergedKey := []byte("")
	mergedKey = append(mergedKey, key1[0:v1]...)
	mergedKey = append(mergedKey, key2[v1:v2]...)
	log.Function("Merging keys")
	return mergedKey, nil
}
