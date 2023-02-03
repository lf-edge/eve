// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"os"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

const (
	srcDirRoot = types.PersistDir + "/downloads"
	dstDir     = types.SealedDirName + "/verifier/verified"
)

// Move files from /persist/downloads/<objType>/verified/<UPPER CASE SHA>/<file>
// to /persist/vault/verifier/verified/<lower case sha>

func renameVerifiedFiles(ctxPtr *ucContext) error {
	log.Functionf("renameVerifiedFiles()")
	if _, err := os.Stat(dstDir); err != nil {
		if err := os.MkdirAll(dstDir, 0700); err != nil {
			log.Error(err)
			return err
		}
	}
	renameFiles(srcDirRoot+"/"+types.AppImgObj+"/verified", dstDir,
		ctxPtr.noFlag)
	renameFiles(srcDirRoot+"/"+types.BaseOsObj+"/verified", dstDir,
		ctxPtr.noFlag)
	log.Noticef("renameVerifiedFiles() DONE")
	return nil
}

// If noFlag is set we just log and no file system modifications.
func renameFiles(srcDir string, dstDir string, noFlag bool) {

	log.Functionf("renameFiles(%s, %s, %t)", srcDir, dstDir, noFlag)
	if _, err := os.Stat(dstDir); err != nil {
		if err := os.MkdirAll(dstDir, 0700); err != nil {
			log.Error(err)
			return
		}
	}
	locations, err := os.ReadDir(srcDir)
	if err != nil {
		// Some old directories might not exist
		if !os.IsNotExist(err) {
			log.Errorf("renameFiles read: directory '%s' failed: %v",
				srcDir, err)
		}
		return
	}
	for _, location := range locations {
		sha := strings.ToLower(location.Name())
		dstFile := dstDir + "/" + sha
		// Find single file in srcDir
		innerDir := srcDir + "/" + location.Name()
		files, err := os.ReadDir(innerDir)
		if err != nil {
			log.Errorf("renameFiles: read directory '%s' failed: %v",
				innerDir, err)
			continue
		}
		if len(files) == 0 {
			log.Errorf("renameFiles: read directory '%s' no file",
				innerDir)
			continue
		}
		if len(files) > 1 {
			log.Errorf("renameFiles: read directory '%s' more than one file: %d",
				innerDir, len(files))
			continue
		}
		srcFile := innerDir + "/" + files[0].Name()
		if _, err := os.Stat(srcFile); err != nil {
			log.Errorf("renameFiles: srcFile %s disappeared?: %s",
				srcFile, err)
			continue
		}
		if _, err := os.Stat(dstFile); err == nil {
			log.Warnf("renameFiles: dst %s already exists hence skipped",
				dstFile)
			continue
		}
		if noFlag {
			log.Functionf("renameFiles: dryrun from %s to %s",
				srcFile, dstFile)
		} else {
			// Must copy due to fscrypt
			// Use atomic rename
			copyRenameDelete(srcFile, dstFile)
		}
	}
}

// If there are any failures we leave the srcFile in place
func copyRenameDelete(srcFile, dstFile string) {
	dstTmpFile := dstFile + ".tmp"
	if _, err := os.Stat(dstTmpFile); err == nil {
		if err := os.Remove(dstTmpFile); err != nil {
			log.Errorf("Remove tmp file failed: %s", err)
			return
		}
	}
	if err := fileutils.CopyFile(srcFile, dstTmpFile); err != nil {
		log.Errorf("Copy failed: %s", err)
	} else if err := os.Rename(dstTmpFile, dstFile); err != nil {
		log.Errorf("Rename to %s failed: %s", dstFile, err)
	} else {
		if err := os.Remove(srcFile); err != nil {
			log.Errorf("Remove source failed: %s", err)
		}
	}
}
