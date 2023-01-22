// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// measure-config application to measure a content of /config into a PCR
// it does nothing on devices without TPM
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	//TpmDevicePath is the TPM device file path
	TpmDevicePath   = "/dev/tpmrm0"
	configPCRIndex  = 14
	configPCRHandle = tpmutil.Handle(tpm2.PCRFirst + configPCRIndex)
)

type fileInfo struct {
	exist          bool
	measureContent bool
}

type tpmEvent struct {
	data string
	pcr  []byte
}

// we do not measure content of following files
// because they are unique for each device
func getExcludeList() []string {
	return []string{
		"/config/tpm_credential",
		"/config/device.cert.pem",
		"/config/device.key.pem",
		"/config/onboard.cert.pem",
		"/config/onboard.key.pem",
		"/config/soft_serial",
	}
}

func isInExcludeList(path string) bool {
	for _, file := range getExcludeList() {
		if file == path {
			return true
		}
	}
	return false
}

// these file may appear later on the device and we record the
// fact that file exists. during attestation process we can detect
// this fact by comparing saved and current event log
func getDangerousList() []string {
	return []string{
		"/config/bootstrap-config.pb",
		"/config/DevicePortConfig/override.json",
		"/config/GlobalConfig/global.json",
		"/config/Force-API-V1",
	}
}

func sha256sumForFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func sha256sumString(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

func measureFileContent(filePath string, tpm io.ReadWriter) (*tpmEvent, error) {
	hash, err := sha256sumForFile(filePath)

	if err != nil {
		return nil, fmt.Errorf("cannot measure %s :%v", filePath, err)
	}

	eventData := fmt.Sprintf("file:%s hash:%s", filePath, hash)

	// it seems PCRExtend expects a hash not data itself.
	eventDataHash := sha256sumString(eventData)

	err = tpm2.PCREvent(tpm, configPCRHandle, eventDataHash[:])

	if err != nil {
		return nil, fmt.Errorf("cannot measure %s. couldn't extend PCR: %v", filePath, err)
	}

	pcr, err := readConfigPCR(tpm)

	if err != nil {
		return nil, fmt.Errorf("cannot measure %s. couldn't read PCR: %v", filePath, err)
	}

	return &tpmEvent{eventData, pcr}, nil
}

func measureFilePath(filePath string, tpm io.ReadWriter, exist bool) (*tpmEvent, error) {
	eventData := fmt.Sprintf("file:%s exist:%t", filePath, exist)
	// it seems PCRExtend expects a hash not data itself.
	eventDataHash := sha256sumString(eventData)

	err := tpm2.PCREvent(tpm, configPCRHandle, eventDataHash[:])

	if err != nil {
		return nil, fmt.Errorf("cannot measure path %s. couldn't extend PCR: %v", filePath, err)
	}

	pcr, err := readConfigPCR(tpm)

	if err != nil {
		return nil, fmt.Errorf("cannot measure path %s. couldn't read PCR: %v", filePath, err)
	}

	return &tpmEvent{eventData, pcr}, nil
}

func getFileMap() (map[string]fileInfo, error) {
	files := make(map[string]fileInfo)

	walkErr := filepath.Walk("/config",
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}
			// may mark file as excluded but we will measure presence/absence
			files[path] = fileInfo{exist: true, measureContent: !isInExcludeList(path)}
			return nil
		})
	if walkErr != nil {
		return nil, walkErr
	}

	// for every file in both exclude and risky lists add entries so the list of files
	// is always the same across all devices in the world
	for _, file := range getExcludeList() {
		_, found := files[file]
		if !found {
			files[file] = fileInfo{exist: false, measureContent: false}
		}
	}

	for _, file := range getDangerousList() {
		_, found := files[file]
		if !found {
			files[file] = fileInfo{exist: false, measureContent: false}
		}
	}

	return files, nil
}

func getSortedFileList(files map[string]fileInfo) []string {
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func measureConfig(tpm io.ReadWriter) error {
	files, err := getFileMap()

	if err != nil {
		return fmt.Errorf("cannot get file list: %v", err)
	}

	//get sorted list of files. We must always go the same order
	//otherwise we'll get different PCR value even with exactly the same
	//file names and their content
	fileNames := getSortedFileList(files)

	for _, file := range fileNames {
		info := files[file]
		var event *tpmEvent

		if info.exist {
			if info.measureContent {
				event, err = measureFileContent(file, tpm)
			} else {
				event, err = measureFilePath(file, tpm, true)
			}
		} else {
			event, err = measureFilePath(file, tpm, false)
		}
		if err != nil {
			return fmt.Errorf("cannot measure %s: %v", file, err)
		}
		//Now we have a new value of PCR and an event
		//TODO: add events to the event log
		// for now just print our measurements to boot log
		log.Printf("%s pcr:%s", event.data, hex.EncodeToString(event.pcr))
	}
	return nil
}

func readConfigPCR(tpm io.ReadWriter) ([]byte, error) {
	pcr, err := tpm2.ReadPCR(tpm, configPCRIndex, tpm2.AlgSHA256)

	if err != nil {
		return nil, fmt.Errorf("cannot read PCR %d: %v", configPCRIndex, err)
	}
	return pcr, nil
}

// Some file like generated certificates do not exist during the installation.
// do we care? it seems nobody is using eve just after installation.
// live image won't report the same PCR values as installed EVE
func main() {
	tpm, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		log.Printf("couldn't open TPM device %s. Exiting", TpmDevicePath)
		return
	}
	defer tpm.Close()

	err = measureConfig(tpm)

	if err != nil {
		log.Fatal(err)
	}
}
