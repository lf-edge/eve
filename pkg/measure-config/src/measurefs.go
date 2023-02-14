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
	//PCREvent (TPM2_PCR_Event) supports event size of maximum 1024 bytes.
	maxEventDataSize = 1024
)

type fileInfo struct {
	exist          bool
	measureContent bool
}

type tpmEvent struct {
	data string
	pcr  []byte
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

func performMeasurement(filePath string, tpm io.ReadWriter, exist bool, content bool) (*tpmEvent, error) {
	var eventData string
	if content {
		hash, err := sha256sumForFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("cannot measure %s :%v", filePath, err)
		}
		eventData = fmt.Sprintf("file:%s exist:true content-hash:%s", filePath, hash)
	} else {
		eventData = fmt.Sprintf("file:%s exist:%t", filePath, exist)
	}

	// Loop over the data and if it is larger than 1024 (max size PCREvent consumes)
	// break it into 1024 bytes chunks, otherwise just loop once and pass data to PCREvent.
	for offset, length := 0, 0; offset < len(eventData); offset += length {
		length = min(maxEventDataSize, len(eventData)-offset)
		// PCREvent internally hashes the data with all supported algorithms
		// associated with the PCR banks, and extends them all before return.
		err := tpm2.PCREvent(tpm, configPCRHandle, []byte(eventData[offset:offset+length]))
		if err != nil {
			return nil, fmt.Errorf("cannot measure %s. couldn't extend PCR: %v", filePath, err)
		}
	}

	pcr, err := readConfigPCR(tpm)
	if err != nil {
		return nil, fmt.Errorf("cannot measure %s. couldn't read PCR: %v", filePath, err)
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
				event, err = performMeasurement(file, tpm, true, true)
			} else {
				event, err = performMeasurement(file, tpm, true, false)
			}
		} else {
			event, err = performMeasurement(file, tpm, false, false)
		}
		if err != nil {
			return fmt.Errorf("cannot measure %s: %v", file, err)
		}
		//Now we have a new value of PCR and an event
		//TODO: add events to the event log, if event data exceeds 1024 bytes,
		// make sure to break it into 1024 bytes chunks with added indicators
		// (e.g. part n of m) to be able to reconstruct the even data for validation.
		// for now we just print our measurements to boot log.
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
