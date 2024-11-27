// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
)

var (
	// initial key, keep it secret, keep it safe
	sk0Test = []byte{
		0x12, 0x34, 0x56, 0x78,
		0x9A, 0xBC, 0xDE, 0xF0,
		0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88,
	}
)

const (
	// TODO : fix this paths
	testDirPrefix = "/tmp/seclog"
	logFile       = "/home/shah/shah-dev/eve/pkg/newlog/testdata/dev.log.sample"
)

func makeTestDirs() {
	uploadDevDir = path.Join(testDirPrefix, "devupload")
	uploadAppDir = path.Join(testDirPrefix, "appupload")
	collectDir = path.Join(testDirPrefix, "collect")

	_ = os.MkdirAll(uploadDevDir, 0777)
	_ = os.MkdirAll(uploadAppDir, 0777)
	_ = os.MkdirAll(collectDir, 0777)
}

func removeTestDirs() {
	os.RemoveAll(testDirPrefix)
}

func listFilesInDir(dir string) []string {
	files, _ := os.ReadDir(dir)
	var filenames []string
	for _, f := range files {
		filenames = append(filenames, path.Join(dir, f.Name()))
	}
	return filenames
}

func getLogVerficiationMetadata(gwComment string) ([]byte, uint64, error) {
	var jsonMap map[string]interface{}
	err := json.Unmarshal([]byte(gwComment), &jsonMap)
	if err != nil {
		return nil, 0, fmt.Errorf("Failed to unmarshal metadata: %s", err)
	}

	macStr, ok := jsonMap["aggSig"].(string)
	if !ok {
		return nil, 0, fmt.Errorf("Failed to find signature in metadata")
	}

	mac, err := base64.StdEncoding.DecodeString(macStr)
	if err != nil {
		return nil, 0, fmt.Errorf("Failed to decode signature: %s", err)
	}

	iter, ok := jsonMap["keyIter"].(float64)
	if !ok {
		return nil, 0, fmt.Errorf("Failed to find keyIteration in metadata")
	}

	return mac, uint64(iter), nil
}

func copyFile(src string, dst string) {
	data, _ := os.ReadFile(src)
	_ = os.WriteFile(dst, data, 0777)
}

func TestSingleSecureLogVerification(t *testing.T) {
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "seclog_test", os.Getpid())
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)

	// setup the test environment
	makeTestDirs()
	defer removeTestDirs()

	scr := logFile
	dst := path.Join(collectDir, "dev.log.sample")
	copyFile(scr, dst)

	var fileinfo fileChanInfo
	fileinfo.notUpload = true
	fileinfo.tmpfile = dst
	fileinfo.inputSize = 0

	// evolve the key, for good measure.
	intialKey := evolveKey(sk0Test, 100)
	secLog.keyIter = 100
	secLog.key = intialKey

	// process the log entries and create the gzipped log file
	doMoveCompressFileSecure(ps, fileinfo)

	// get the log gzipped file path
	logGzipped := listFilesInDir(uploadDevDir)[0]
	rf, err := os.Open(logGzipped)
	if err != nil {
		t.Fatalf("Failed to open %s: %s", logGzipped, err)
	}
	defer rf.Close()

	gr, err := gzip.NewReader(rf)
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %s", err)
	}
	defer gr.Close()

	// read the batch metadata from gzipped metadata.
	aggSig, keyIter, err := getLogVerficiationMetadata(gr.Comment)
	if err != nil {
		t.Fatalf("Failed to read secure log metadata from %s: %s", logGzipped, err)
	}

	logs := make([][]byte, 0)
	scanner := bufio.NewScanner(gr)
	for scanner.Scan() {
		if !json.Valid(scanner.Bytes()) {
			t.Fatalf("Invalid JSON: %s", scanner.Text())
		}
		logs = append(logs, append([]byte(nil), scanner.Bytes()...))
	}

	// evolve the key to the same iteration as the one used to sign the log.
	verifKey := evolveKey(sk0Test, keyIter)
	// verify the log
	res := fssAggVer(verifKey, aggSig, logs)
	if !res {
		t.Fatalf("Secure log verification failed")
	}
}

func TestMultipleSecureLogVerification(t *testing.T) {
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "seclog_test", os.Getpid())
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)

	// setup the test environment
	makeTestDirs()
	defer removeTestDirs()

	scr := logFile
	dst := path.Join(collectDir, "dev.log.sample")
	copyFile(scr, dst)

	var fileinfo fileChanInfo
	fileinfo.notUpload = true
	fileinfo.tmpfile = dst
	fileinfo.inputSize = 0

	// evolve the key, for good measure.
	intialKey := evolveKey(sk0Test, 100)
	secLog.keyIter = 100
	secLog.key = intialKey

	// lower the maxGzipFileSize to multiple batches
	maxGzipFileSize = 1000

	// process the log entries and create the gzipped log file
	doMoveCompressFileSecure(ps, fileinfo)

	// get the log gzipped file path
	allLogs := listFilesInDir(uploadDevDir)
	for _, logGzipped := range allLogs {
		rf, err := os.Open(logGzipped)
		if err != nil {
			t.Fatalf("Failed to open %s: %s", logGzipped, err)
		}
		defer rf.Close()

		gr, err := gzip.NewReader(rf)
		if err != nil {
			t.Fatalf("Failed to create gzip reader: %s", err)
		}
		defer gr.Close()

		// read the batch metadata from gzipped metadata.
		aggSig, keyIter, err := getLogVerficiationMetadata(gr.Comment)
		if err != nil {
			t.Fatalf("Failed to read secure log metadata from %s: %s", logGzipped, err)
		}

		logs := make([][]byte, 0)
		scanner := bufio.NewScanner(gr)
		for scanner.Scan() {
			if !json.Valid(scanner.Bytes()) {
				t.Fatalf("Invalid JSON: %s", scanner.Text())
			}
			logs = append(logs, append([]byte(nil), scanner.Bytes()...))
		}

		t.Logf("Verifying log with key iteration : %d", keyIter)
		t.Logf("Number of log entries: %d", len(logs))
		t.Logf("Batch aggregated signature: %x", aggSig)
		t.Log("----------------------------------------")

		// evolve the key to the same iteration as the one used to sign the log.
		verifKey := evolveKey(sk0Test, keyIter)
		// verify the log
		res := fssAggVer(verifKey, aggSig, logs)
		if !res {
			t.Fatalf("Secure log verification failed for %s", logGzipped)
		}
	}
}

func TestContentIntegritySecureLogVerification(t *testing.T) {
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "seclog_test", os.Getpid())
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)

	// setup the test environment
	makeTestDirs()
	defer removeTestDirs()

	scr := logFile
	dst := path.Join(collectDir, "dev.log.sample")
	copyFile(scr, dst)

	var fileinfo fileChanInfo
	fileinfo.notUpload = true
	fileinfo.tmpfile = dst
	fileinfo.inputSize = 0

	// evolve the key, for good measure.
	intialKey := evolveKey(sk0Test, 100)
	secLog.keyIter = 100
	secLog.key = intialKey

	// process the log entries and create the gzipped log file
	doMoveCompressFileSecure(ps, fileinfo)

	// get the log gzipped file path
	logGzipped := listFilesInDir(uploadDevDir)[0]
	rf, err := os.Open(logGzipped)
	if err != nil {
		t.Fatalf("Failed to open %s: %s", logGzipped, err)
	}
	defer rf.Close()

	gr, err := gzip.NewReader(rf)
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %s", err)
	}
	defer gr.Close()

	// read the batch metadata from gzipped metadata.
	aggSig, keyIter, err := getLogVerficiationMetadata(gr.Comment)
	if err != nil {
		t.Fatalf("Failed to read secure log metadata from %s: %s", logGzipped, err)
	}

	logs := make([][]byte, 0)
	scanner := bufio.NewScanner(gr)
	for scanner.Scan() {
		if !json.Valid(scanner.Bytes()) {
			t.Fatalf("Invalid JSON: %s", scanner.Text())
		}
		logs = append(logs, append([]byte(nil), scanner.Bytes()...))
	}

	if len(logs) < 3 {
		t.Fatalf("Not enough log entries to content integrity")
	}

	// get a ranom log entry and corrupt it
	corruptLogIdx := rand.Intn(len(logs))
	logs[corruptLogIdx] = []byte("corrupted log entry")

	// evolve the key to the same iteration as the one used to sign the log.
	verifKey := evolveKey(sk0Test, keyIter)
	// verify the log
	res := fssAggVer(verifKey, aggSig, logs)
	if res != false {
		t.Fatalf("Expected secure log verification to failed")
	}
}

func TestStreamIntegritySecureLogVerification(t *testing.T) {
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "seclog_test", os.Getpid())
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)

	// setup the test environment
	makeTestDirs()
	defer removeTestDirs()

	scr := logFile
	dst := path.Join(collectDir, "dev.log.sample")
	copyFile(scr, dst)

	var fileinfo fileChanInfo
	fileinfo.notUpload = true
	fileinfo.tmpfile = dst
	fileinfo.inputSize = 0

	// evolve the key, for good measure.
	intialKey := evolveKey(sk0Test, 100)
	secLog.keyIter = 100
	secLog.key = intialKey

	// process the log entries and create the gzipped log file
	doMoveCompressFileSecure(ps, fileinfo)

	// get the log gzipped file path
	logGzipped := listFilesInDir(uploadDevDir)[0]
	rf, err := os.Open(logGzipped)
	if err != nil {
		t.Fatalf("Failed to open %s: %s", logGzipped, err)
	}
	defer rf.Close()

	gr, err := gzip.NewReader(rf)
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %s", err)
	}
	defer gr.Close()

	// read the batch metadata from gzipped metadata.
	aggSig, keyIter, err := getLogVerficiationMetadata(gr.Comment)
	if err != nil {
		t.Fatalf("Failed to read secure log metadata from %s: %s", logGzipped, err)
	}

	logs := make([][]byte, 0)
	scanner := bufio.NewScanner(gr)
	for scanner.Scan() {
		if !json.Valid(scanner.Bytes()) {
			t.Fatalf("Invalid JSON: %s", scanner.Text())
		}
		logs = append(logs, append([]byte(nil), scanner.Bytes()...))
	}

	if len(logs) < 3 {
		t.Fatalf("Not enough log entries to stream integrity")
	}

	// get a ranom log entry and delete it
	corruptLogIdx := rand.Intn(len(logs))
	logs = append(logs[:corruptLogIdx], logs[corruptLogIdx+1:]...)

	// evolve the key to the same iteration as the one used to sign the log.
	verifKey := evolveKey(sk0Test, keyIter)
	// verify the log
	res := fssAggVer(verifKey, aggSig, logs)
	if res != false {
		t.Fatalf("Expected secure log verification to failed")
	}
}

func TestTruncationSecureLogVerification(t *testing.T) {
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "seclog_test", os.Getpid())
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)

	// setup the test environment
	makeTestDirs()
	defer removeTestDirs()

	scr := logFile
	dst := path.Join(collectDir, "dev.log.sample")
	copyFile(scr, dst)

	var fileinfo fileChanInfo
	fileinfo.notUpload = true
	fileinfo.tmpfile = dst
	fileinfo.inputSize = 0

	// evolve the key, for good measure.
	intialKey := evolveKey(sk0Test, 100)
	secLog.keyIter = 100
	secLog.key = intialKey

	// process the log entries and create the gzipped log file
	doMoveCompressFileSecure(ps, fileinfo)

	// get the log gzipped file path
	logGzipped := listFilesInDir(uploadDevDir)[0]
	rf, err := os.Open(logGzipped)
	if err != nil {
		t.Fatalf("Failed to open %s: %s", logGzipped, err)
	}
	defer rf.Close()

	gr, err := gzip.NewReader(rf)
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %s", err)
	}
	defer gr.Close()

	// read the batch metadata from gzipped metadata.
	aggSig, keyIter, err := getLogVerficiationMetadata(gr.Comment)
	if err != nil {
		t.Fatalf("Failed to read secure log metadata from %s: %s", logGzipped, err)
	}

	logs := make([][]byte, 0)
	scanner := bufio.NewScanner(gr)
	for scanner.Scan() {
		if !json.Valid(scanner.Bytes()) {
			t.Fatalf("Invalid JSON: %s", scanner.Text())
		}
		logs = append(logs, append([]byte(nil), scanner.Bytes()...))
	}

	if len(logs) < 3 {
		t.Fatalf("Not enough log entries to test truncation")
	}

	// delete a few log entries form the tail
	logsTail := logs[:len(logs)-2]

	// evolve the key to the same iteration as the one used to sign the log.
	verifKey := evolveKey(sk0Test, keyIter)
	// verify the log
	res := fssAggVer(verifKey, aggSig, logsTail)
	if res != false {
		t.Fatalf("Expected secure log verification to failed (tail truncation)")
	}

	// delete a few log entries form the head
	logsHead := logs[2:]

	// evolve the key to the same iteration as the one used to sign the log.
	verifKey = evolveKey(sk0Test, keyIter)
	// verify the log
	res = fssAggVer(verifKey, aggSig, logsHead)
	if res != false {
		t.Fatalf("Expected secure log verification to failed (head truncation)")
	}
}
