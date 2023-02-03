// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	startCopyMessage = "+++Start-Copy+++"
	fileCopyDir      = "/download/"
)

type copyType int

const (
	unknownCopy copyType = iota
	copySingleFile
	copyLogFiles
	copyTarFiles
	copyTechSupport
)

var (
	isSvrCopy  bool // server side
	copyMsgChn chan []byte
	lastPerc   int64
	barDone    chan struct{}
)

type copyFile struct {
	TokenHash []byte `json:"tokenHash"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	Sha256    string `json:"sha256"`
	ModTsec   int64  `json:"modtsec"`
}

type fileCopyStatus struct {
	gotFileInfo bool
	cType       copyType
	filename    string
	fileSize    int64
	fileHash    string
	currSize    int64
	modTime     time.Time
	buf         []byte
	f           *os.File
}

func runCopy(opt string) {
	path := strings.SplitN(opt, "cp/", 2)
	if len(path) != 2 {
		fmt.Printf("cp needs a cp/ and path input\n")
		return
	}
	file := path[1]
	info, err := os.Stat(file)
	if err != nil {
		fmt.Printf("os stat error %v\n", err)
		return
	}

	ok := checkBlockedDirs(file)
	if !ok {
		fmt.Printf("directory is blocked for file copy: %s\n", file)
		return
	}

	ok = checkBlockedFileSuffix(info.Name())
	if !ok {
		fmt.Printf("file %s can not be copied\n", file)
		return
	}

	cfile := copyFile{
		Name:    info.Name(),
		Size:    info.Size(),
		ModTsec: info.ModTime().Unix(),
		Sha256:  fmt.Sprintf("%x", getFileSha256(file)),
	}
	jbytes, err := json.Marshal(cfile)
	if err != nil {
		fmt.Printf("json marshal error %v\n", err)
		return
	}

	// send file information to client side and wait for signal to start copy
	err = addEnvelopeAndWriteWss(jbytes, false)
	if err != nil {
		fmt.Printf("sign and write error: %v\n", err)
		return
	}

	// server side set
	isSvrCopy = true
	copyMsgChn = make(chan []byte)
	ahead := make(chan struct{})
	done := make(chan struct{})
	t := time.NewTimer(30 * time.Second)
	readerRunning := true

	go func() {
		for {
			select {
			case message := <-copyMsgChn:
				if !strings.Contains(string(message), startCopyMessage) {
					log.Noticef("webc read message. %s", string(message))
					readerRunning = false
					if !isClosed(ahead) {
						close(ahead)
					}
					isSvrCopy = false
					return
				} else {
					// start copy file transfer
					close(ahead)
				}

			case <-t.C:
				readerRunning = false
				if !isClosed(ahead) {
					close(ahead)
				}
				isSvrCopy = false
				return

			case <-done:
				t.Stop()
				isSvrCopy = false
				return
			}
		}
	}()

	<-ahead
	if !readerRunning {
		return
	}
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("os open error %v\n", err)
		return
	}
	defer f.Close()

	buffer := make([]byte, 8192)
	totalBytes := 0
	for {
		n, err := f.Read(buffer)
		if err != nil {
			fmt.Printf("file read error %v\n", err)
			return
		}

		err = addEnvelopeAndWriteWss(buffer[:n], false)
		if err != nil {
			fmt.Printf("file write to wss error %v\n", err)
			return
		}
		totalBytes += n
		if totalBytes >= int(cfile.Size) {
			break
		}
	}
	close(done)
}

// client side receive copied file
func recvCopyFile(msg []byte, fstatus *fileCopyStatus, mtype int) {
	var info copyFile
	if !fstatus.gotFileInfo {
		err := json.Unmarshal(msg, &info)
		if err != nil {
			fmt.Printf("%s\n", []byte(msg))
			if bytes.Contains(msg, []byte("<techsupport>")) {
				barDone = make(chan struct{})
				go waitAndPrintBar(barDone)
			}
			return
		}

		fmt.Printf("\n\n")
		if barDone != nil {
			close(barDone)
		}

		lastPerc = 0
		fstatus.filename = info.Name
		fstatus.fileSize = info.Size
		fstatus.fileHash = info.Sha256
		fstatus.modTime = time.Unix(info.ModTsec, 0)
		fstatus.buf = make([]byte, info.Size)

		fmt.Printf(" transfer file: name %s, size %d\n", fstatus.filename, fstatus.fileSize)

		_, err = os.Stat(fileCopyDir)
		if err != nil {
			sendCopyDone("file stat ", err)
			return
		}
		filePath := filepath.Join(fileCopyDir, fstatus.filename)
		// check if we receive valid filename to avoid touch of files outside fileCopyDir
		if !strings.HasPrefix(filePath, fileCopyDir) {
			sendCopyDone("filename check ", fmt.Errorf("filename has unexpected path inside the name"))
			return
		}
		fstatus.f, err = os.Create(filePath)
		if err != nil {
			sendCopyDone("file create", err)
			return
		}
		fstatus.gotFileInfo = true

		err = addEnvelopeAndWriteWss([]byte(startCopyMessage), false)
		if err != nil {
			sendCopyDone("write start copy failed", err)
		}
		return
	}
	if mtype == websocket.TextMessage {
		fmt.Printf("recv text msg, exit\n")
		fstatus.cType = unknownCopy
		fstatus.f.Close()
		return
	}

	n, err := fstatus.f.Write(msg)
	if err != nil {
		fstatus.cType = unknownCopy
		fstatus.f.Close()
		fmt.Printf("file write error: %v\n", err)
		return
	}

	lastSize := fstatus.currSize
	fstatus.currSize += int64(n)
	checkAndPrintBar(lastSize, fstatus.currSize, fstatus.fileSize, &lastPerc)
	if fstatus.currSize >= fstatus.fileSize {
		fstatus.f.Close()
		shaStr := fmt.Sprintf("%x", getFileSha256(fileCopyDir+fstatus.filename))
		if shaStr == fstatus.fileHash {
			err := os.Chtimes(fileCopyDir+fstatus.filename, fstatus.modTime, fstatus.modTime)
			if err != nil {
				fmt.Printf("modify file time: %v\n", err)
			}
			if fstatus.cType == copyTarFiles {
				ungzipFile(fstatus.filename)
			} else if fstatus.cType == copyLogFiles {
				untarLogfile(fstatus.filename)
			}
		} else {
			fmt.Printf("\n file sha256 different. %s, should be %s\n", shaStr, fstatus.fileHash)
		}
		sendCopyDone(closeMessage, nil)
		fstatus.cType = unknownCopy
	}
}

func checkAndPrintBar(lastSize, currSize, totalSize int64, lastPerc *int64) {
	currPerc := currSize * 100 / totalSize
	for currPerc-*lastPerc > 2 {
		fmt.Printf("=")
		*lastPerc += 2
	}
	if currSize == totalSize {
		fmt.Printf("\n")
	}
}

func waitAndPrintBar(barDone chan struct{}) {

	time.Sleep(2 * time.Second)
	fmt.Printf("\n")
	ticker := time.NewTicker(500 * time.Millisecond)
	for {
		select {
		case <-ticker.C:
			fmt.Printf("+")
		case <-barDone:
			fmt.Printf("\n")
			return
		}
	}
}

func sendCopyDone(context string, err error) {
	if err != nil {
		fmt.Printf("%s error: %v\n", context, err)
	}
	err = addEnvelopeAndWriteWss([]byte(context), true)
	if err != nil {
		fmt.Printf("sign and write error: %v\n", err)
	}
}

func untarLogfile(downloadedFile string) {
	cmdStr := "cd " + fileCopyDir + "; tar xvf " + downloadedFile
	untarCmd := exec.Command("sh", "-c", cmdStr)
	err := untarCmd.Run()
	if err != nil {
		fmt.Printf("untar error: %v\n", err)
	} else {
		_ = os.Remove(fileCopyDir + downloadedFile)
	}

	fileStr := strings.SplitN(downloadedFile, ".tar", 2)
	if len(fileStr) != 2 {
		return
	}
	logSaveDir := fileCopyDir + fileStr[0]
	fmt.Printf("\n log files saved at %s\n\n", logSaveDir)
	files, err := os.ReadDir(logSaveDir)
	if err != nil {
		fmt.Printf("read %s error, %v\n", logSaveDir, err)
		return
	}
	for _, f := range files {
		if info, err := f.Info(); err == nil {
			fmt.Printf("file: %s, size %d\n", f.Name(), info.Size())
		}
	}

	unpackLogfiles(fileCopyDir+fileStr[0], files)
}

func runCopyLogfiles(logfiles []logfiletime, time1 int64) {

	timeStr := getFileTimeStr(time.Unix(time1, 0))
	destinationfile := "/tmp/logfiles-" + timeStr + ".tar"

	// no need for compression since the logfiles are already in
	// gzip compressed format
	tarfile, err := os.Create(destinationfile)
	if err != nil {
		log.Errorf("runCopyLogfiles create error %v", err)
		return
	}
	defer tarfile.Close()

	var fileWriter io.WriteCloser = tarfile

	tarfileWriter := tar.NewWriter(fileWriter)
	defer tarfileWriter.Close()

	for _, logfile := range logfiles {
		fileInfo, err := os.Stat(logfile.filepath)
		if err != nil {
			log.Errorf("runCopyLogfiles can not stat: %v", err)
			continue
		}
		file, err := os.Open(logfile.filepath)
		if err != nil {
			log.Errorf("runCopyLogfiles file open error: %v", err)
			continue
		}
		defer file.Close()

		// prepare the tar header
		header := new(tar.Header)
		header.Name = "logfiles-" + timeStr + "/" + filepath.Base(file.Name())
		header.Size = fileInfo.Size()
		header.Mode = int64(fileInfo.Mode())
		header.ModTime = fileInfo.ModTime()

		err = tarfileWriter.WriteHeader(header)
		if err != nil {
			log.Errorf("runCopyLogfiles write header error: %v", err)
			continue
		}

		_, err = io.Copy(tarfileWriter, file)
		if err != nil {
			log.Errorf("runCopyLogfiles copy file error: %v", err)
			continue
		}
		file.Close()
	}
	tarfileWriter.Close()
	tarfile.Close()

	// use the normal 'cp' utility to transfer the tar file over
	runCopy("cp/" + destinationfile)
	_ = os.Remove(destinationfile)
}
