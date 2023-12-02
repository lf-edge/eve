// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// measure-config application to measure a content of /config into a PCR
// it does nothing on devices without TPM
package main

import (
	"crypto/sha256"
	"encoding/binary"
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
	maxEventDataSize     = 1024
	evAlgSHA256          = 0xb
	evEfiAction          = 0x80000007
	measurefsTpmEventLog = "/persist/status/measurefs_tpm_event_log"
)

// the following structs created based on "Crypto Agile Log Entry Format"
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf
type tcgPcrEvent2 struct {
	PcrIndex  uint32
	EventType uint32
	Digest    tpmlDigestValues
	EventSize uint32
	Event     []uint8
}

type tpmlDigestValues struct {
	Count   uint32
	Digests []tpmtHa
}

type tpmtHa struct {
	HashAlg    uint16
	DigestData []byte
}

type fileInfo struct {
	exist          bool
	measureContent bool
}

type tpmEvent struct {
	tcgEvent tcgPcrEvent2
	data     string
	pcr      []byte
}

func (event *tcgPcrEvent2) MarshalBinary() ([]byte, error) {
	buffer := make([]byte, event.size())
	offset := 0

	binary.LittleEndian.PutUint32(buffer[offset:], event.PcrIndex)
	offset += 4

	binary.LittleEndian.PutUint32(buffer[offset:], event.EventType)
	offset += 4

	digestBytes, err := event.Digest.MarshalBinary()
	if err != nil {
		return nil, err
	}

	copy(buffer[offset:], digestBytes)
	offset += len(digestBytes)

	binary.LittleEndian.PutUint32(buffer[offset:], event.EventSize)
	offset += 4

	copy(buffer[offset:], event.Event)

	return buffer, nil
}

func (event *tcgPcrEvent2) size() int {
	return 4 + 4 + event.Digest.size() + 4 + len(event.Event)
}

func (digestValue *tpmlDigestValues) MarshalBinary() ([]byte, error) {
	buffer := make([]byte, digestValue.size())
	offset := 0

	binary.LittleEndian.PutUint32(buffer[offset:], digestValue.Count)
	offset += 4

	for _, digest := range digestValue.Digests {
		digestBytes, err := digest.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(buffer[offset:], digestBytes)
		offset += len(digestBytes)
	}

	return buffer, nil
}

func (digestValue *tpmlDigestValues) size() int {
	size := 4
	for _, digest := range digestValue.Digests {
		size += digest.size()
	}
	return size
}

func (digest *tpmtHa) MarshalBinary() ([]byte, error) {
	buffer := make([]byte, digest.size())
	offset := 0

	binary.LittleEndian.PutUint16(buffer[offset:], digest.HashAlg)
	offset += 2

	copy(buffer[offset:], digest.DigestData)

	return buffer, nil
}

func (digest *tpmtHa) size() int {
	return 2 + len(digest.DigestData)
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

	// Max size for PCREvent data is 1024 bytes, truncate the file path if it
	// is longer than 512 bytes.
	eventFilePath := filePath
	if len(filePath) > 512 {
		// in this case just get the file name, it maxes out at 255 chars.
		eventFilePath = filepath.Base(filePath)
	}

	if content {
		hash, err := sha256sumForFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("can not measure %s :%w", filePath, err)
		}
		eventData = fmt.Sprintf("file:%s exist:true content-hash:%s", eventFilePath, hash)
	} else {
		eventData = fmt.Sprintf("file:%s exist:%t", eventFilePath, exist)
	}

	// PCREvent internally hashes the data with all supported algorithms
	// associated with the PCR banks, and extends them all before return.
	err := tpm2.PCREvent(tpm, configPCRHandle, []byte(eventData))
	if err != nil {
		return nil, fmt.Errorf("can not measure %s. couldn't extend PCR: %w", filePath, err)
	}

	pcr, err := readConfigPCR(tpm)
	if err != nil {
		return nil, fmt.Errorf("can not measure %s. couldn't read PCR: %w", filePath, err)
	}

	eventHash := sha256.Sum256([]byte(eventData))
	tcgEvent := tcgPcrEvent2{
		PcrIndex:  configPCRIndex,
		EventType: evEfiAction,
		Digest: tpmlDigestValues{
			Count: 1,
			Digests: []tpmtHa{
				{
					HashAlg:    evAlgSHA256,
					DigestData: eventHash[:],
				},
			},
		},
		EventSize: uint32(len(eventData)),
		Event:     []uint8(eventData),
	}

	return &tpmEvent{tcgEvent, eventData, pcr}, nil
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

func measureConfig(tpm io.ReadWriter) ([]tcgPcrEvent2, error) {
	files, err := getFileMap()
	events := make([]tcgPcrEvent2, 0)

	if err != nil {
		return []tcgPcrEvent2{}, fmt.Errorf("can not get file list: %w", err)
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
			return []tcgPcrEvent2{}, fmt.Errorf("can not measure %s: %w", file, err)
		}

		//Now we have a new value of PCR and an event
		log.Printf("%s pcr:%s", event.data, hex.EncodeToString(event.pcr))
		events = append(events, event.tcgEvent)
	}

	return events, nil
}

func readConfigPCR(tpm io.ReadWriter) ([]byte, error) {
	pcr, err := tpm2.ReadPCR(tpm, configPCRIndex, tpm2.AlgSHA256)

	if err != nil {
		return nil, fmt.Errorf("can not read PCR %d: %w", configPCRIndex, err)
	}
	return pcr, nil
}

// Some file like generated certificates do not exist during the installation.
// do we care? it seems nobody is using eve just after installation.
// live image won't report the same PCR values as installed EVE
func main() {
	tpm, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		log.Fatalf("couldn't open TPM device %s. Exiting", TpmDevicePath)
	}
	defer tpm.Close()

	events, err := measureConfig(tpm)
	if err != nil {
		log.Fatal(err)
	}

	// loop over events and marshal them to binary
	eventLog := make([]byte, 0)
	for _, event := range events {
		eventBytes, err := event.MarshalBinary()
		if err != nil {
			log.Printf("[WARNING] failed to construct measure-config tpm event log : %v", err)
			return
		}

		eventLog = append(eventLog, eventBytes...)
	}

	// no need for an atomic file operations here, this file is created
	// on every boot.
	file, err := os.Create(measurefsTpmEventLog)
	if err != nil {
		log.Printf("[WARNING] failed to create measure-config tpm event log : %v", err)
		return
	}
	defer file.Close()

	if _, err := file.Write(eventLog); err != nil {
		log.Printf("[WARNING] failed to write measure-config tpm event log : %v", err)
	}
}
