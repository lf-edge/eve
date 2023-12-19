// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	startCopyMessage = "+++Start-Copy+++"
	fileCopyDir      = "/download/"
	// MbpsToBytes - 1 Mbps = 131072 bytes per second, 1,048,576/8
	MbpsToBytes      = 131072
	desiredSpeedMbps = 5       // Rate-Limit to 5Mbps for copying file
	chunkSize        = 32768   // Max chunk bytes (32K) to be sent over websocket connection
	logToTextMaxSize = 5242880 // Skip convert filtes into a single text file if log tarfile > 5Mbytes
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
	chunkCount int
	barDone    chan struct{}
)

type copyFile struct {
	TokenHash []byte `json:"tokenHash"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	DirSize   int64  `json:"dirsize"`
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
	f           *os.File
	startTime   time.Time
}

// dirEntry is a custom struct that similar to the os.DirEntry
type dirEntry struct {
	path string
	info os.FileInfo
}

// copy file to remote client, if is tar op, the file transfer is
// handled by the caller. In log copy-logfiles tar case, dirSize is zero
func runCopy(opt string, tarDirSize *int64) error {
	path := strings.SplitN(opt, "cp/", 2)
	if len(path) != 2 {
		fmt.Printf("cp needs a cp/ and path input\n")
		return fmt.Errorf("cp command error")
	}

	var cfile copyFile
	file := path[1]
	if tarDirSize != nil { // for copying in tar oper, we may only have directory 'du' size
		cfile = copyFile{
			Name:    file,
			ModTsec: time.Now().Unix(),
			DirSize: *tarDirSize,
		}
	} else {
		info, err := os.Stat(file)
		if err != nil {
			fmt.Printf("os stat error %v\n", err)
			return fmt.Errorf("cp command error")
		}

		ok := checkBlockedDirs(file)
		if !ok {
			fmt.Printf("directory is blocked for file copy: %s\n", file)
			return fmt.Errorf("cp command error")
		}

		ok = checkBlockedFileSuffix(info.Name())
		if !ok {
			fmt.Printf("file %s can not be copied\n", file)
			return fmt.Errorf("cp command error")
		}

		cfile = copyFile{
			Name:    info.Name(),
			Size:    info.Size(),
			ModTsec: info.ModTime().Unix(),
			Sha256:  fmt.Sprintf("%x", getFileSha256(file)),
		}
	}
	jbytes, err := json.Marshal(cfile)
	if err != nil {
		fmt.Printf("json marshal error %v\n", err)
		return fmt.Errorf("cp command json error")
	}

	// send file information to client side and wait for signal to start copy
	err = addEnvelopeAndWriteWss(jbytes, false)
	if err != nil {
		fmt.Printf("sign and write error: %v\n", err)
		return fmt.Errorf("cp command write file header error")
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
	if tarDirSize != nil { // the caller will handle the file transfer operation
		log.Functionf("runCopy: received from client to go ahead")
		return nil
	}

	if !readerRunning {
		return nil
	}
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("os open error %v\n", err)
		return fmt.Errorf("cp command error")
	}
	defer f.Close()

	// the delay is only related to the transfer chunksize, independent of total size of the file
	sleepDuration := getSleepDuration(chunkSize)
	buffer := make([]byte, chunkSize)
	totalBytes := 0
	for {
		if lostClientPeer { // in the middle of transferring file, if client is gone, jump out
			log.Functionf("createArchive: client is gone. Stop transferring files")
			break
		}
		n, err := f.Read(buffer)
		if err != nil {
			fmt.Printf("file read error %v\n", err)
			return fmt.Errorf("cp command error")
		}

		err = addEnvelopeAndWriteWss(buffer[:n], false)
		if err != nil {
			fmt.Printf("file write to wss error %v\n", err)
			return fmt.Errorf("cp command error")
		}
		totalBytes += n
		if totalBytes >= int(cfile.Size) {
			break
		}
		if !disableRateLimit {
			time.Sleep(sleepDuration)
		}
	}
	close(done)
	return nil
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
		chunkCount = 0
		fstatus.filename = info.Name
		fstatus.fileSize = info.Size
		fstatus.fileHash = info.Sha256
		fstatus.modTime = time.Unix(info.ModTsec, 0)

		transferStr := fmt.Sprintf(" transfer file: name %s", fstatus.filename)
		if fstatus.fileSize != 0 { // normal copy a file over
			transferStr = transferStr + fmt.Sprintf(", size %d\n", fstatus.fileSize)
		} else if info.DirSize != 0 { // transfer over a tar directory
			transferStr = transferStr + fmt.Sprintf(", directory size %d\n", info.DirSize)
		} // otherwise, it's log search in a time range, copy-logfiles
		fmt.Printf("%s\n", transferStr)

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

		// send to server, go ahead and start transfer
		err = addEnvelopeAndWriteWss([]byte(startCopyMessage), false)
		if err != nil {
			sendCopyDone("write start copy failed", err)
		}
		return
	}

	var tarfileDone bool
	var serverSentSize int
	if mtype == websocket.TextMessage {
		// when transferred file is w/ tar operation, we don't know the file size,
		// server side sends a copy-done message with total sent size
		if fstatus.fileSize == 0 && bytes.Contains(msg, []byte(tarCopyDoneMsg)) {
			re := regexp.MustCompile(`\+(\d+)\+\+\+`)
			// Find the first match
			match := re.FindStringSubmatch(string(msg))
			// Check if there is a match
			if len(match) >= 2 {
				// Extract the captured numeric part
				number := match[1]
				num, err := strconv.Atoi(number)
				if err == nil {
					serverSentSize = num
				}
			}
			tarfileDone = true
		} else {
			fmt.Printf("recv text msg, exit\n")
			fstatus.cType = unknownCopy
			fstatus.f.Close()
			return
		}
	}

	var n int
	var err error
	if !tarfileDone {
		n, err = fstatus.f.Write(msg)
		if err != nil {
			fstatus.cType = unknownCopy
			fstatus.f.Close()
			fmt.Printf("file write error: %v\n", err)
			return
		}
	}

	if fstatus.currSize == 0 {
		fstatus.startTime = time.Now()
	}
	lastSize := fstatus.currSize
	fstatus.currSize += int64(n)
	if fstatus.fileSize > 0 { // display a moving bar and percentage of progress
		checkAndPrintBar(lastSize, fstatus.currSize, fstatus.fileSize, &lastPerc)
	} else {
		if chunkCount == 0 {
			fmt.Printf("%11d ", 0)
		}
		// since we don't know the final size, print a '+' for every 5 chunks (up to 32K a chunk) received
		// it can take a long time, so not giving impression of system hanging
		if chunkCount%5 == 0 {
			fmt.Print("+")
		}
		chunkCount++
		// for every 100 '+', return cursor back to column zero, print the current downloaded size
		if chunkCount%500 == 0 {
			fmt.Print("\033[2K\r")
			fmt.Printf("%11d ", fstatus.currSize)
		}
	}

	// transfer done
	if (fstatus.fileSize != 0 && fstatus.currSize >= fstatus.fileSize) || tarfileDone {
		fstatus.f.Close()

		if fstatus.fileHash != "" {
			shaStr := fmt.Sprintf("%x", getFileSha256(fileCopyDir+fstatus.filename))
			if shaStr != fstatus.fileHash {
				fmt.Printf("\n file sha256 different. %s, should be %s\n", shaStr, fstatus.fileHash)
			}
		}

		err := os.Chtimes(fileCopyDir+fstatus.filename, fstatus.modTime, fstatus.modTime)
		if err != nil {
			fmt.Printf("modify file time: %v\n", err)
		}
		// Calculate rate in Mbps from client side, and print out for the user
		elapsed := time.Since(fstatus.startTime)
		fileSizeMb := float64(fstatus.currSize) * 8 / 1048576
		rate := fileSizeMb / elapsed.Seconds()
		fmt.Printf("\n transfer rate in %.2f Mbps\n", rate)

		if fstatus.cType == copyLogFiles {
			// this is for command 'log/copy-logfiles [-time <from - to>]'
			// if copy-logfiles in a time range, and the size is not too large (< 5MBytes),
			// then convert the tar file and content of log gzip files into a single text file.
			// Otherwise if the size is large, leave the tar file, let user to uncompress later
			if fstatus.currSize < logToTextMaxSize {
				untarLogfile(fstatus.filename, fstatus.currSize)
			} else {
				fmt.Printf("\nfile size %d, saved at %s\n", fstatus.currSize, fileCopyDir+fstatus.filename)
			}
		}
		transferStr := fmt.Sprintf("\n file %s size %d", fstatus.filename, fstatus.currSize)
		if serverSentSize != 0 && fstatus.currSize != int64(serverSentSize) {
			transferStr = transferStr + fmt.Sprintf(", server sent %d", serverSentSize)
		}
		fmt.Printf("%s\n", transferStr)

		sendCopyDone(closeMessage, nil)
		fstatus.cType = unknownCopy
	}
}

// print the progress bar of the copied file
func checkAndPrintBar(lastSize, currSize, totalSize int64, lastPerc *int64) {
	currPerc := currSize * 100 / totalSize
	done := currSize == totalSize
	if currPerc-*lastPerc > 2 || done {
		//fmt.Printf("=")
		fmt.Print("\r")
		fmt.Printf("[")
		for i := 0; i < int(currPerc); i++ {
			fmt.Print("+")
		}
		for i := int(currPerc); i < 100; i++ {
			fmt.Print("-")
		}
		fmt.Printf("] %d%%", currPerc)
		fmt.Fprint(os.Stdout, "\r")
		*lastPerc += 2
	}
	if done {
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

// untarLogfile - unzip and make into a single .txt
// with sequential log entries for dev and each of the apps
// this is done only if the tar file size is not too large
func untarLogfile(downloadedFile string, filesize int64) {
	fileStr := strings.SplitN(downloadedFile, ".tar", 2)
	if len(fileStr) != 2 {
		return
	}
	logSaveDir := fileCopyDir + fileStr[0]
	fmt.Printf("\n tarfile size %d, untar log files at %s\n\n", filesize, logSaveDir)
	cmdStr := "cd " + fileCopyDir + "; tar xvf " + downloadedFile
	untarCmd := exec.Command("sh", "-c", cmdStr)
	err := untarCmd.Run()
	if err != nil {
		fmt.Printf("untar error: %v\n", err)
	} else {
		_ = os.Remove(fileCopyDir + downloadedFile)
	}

	newlogDir := fileCopyDir + "newlog"
	_, err = os.Stat(newlogDir)
	if err == nil {
		err = os.Rename(newlogDir, logSaveDir)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	fmt.Printf("\n log files saved at %s\n\n", logSaveDir)

	// walk through the downloaded newlog directories, and unzip files into .txt file
	var files []dirEntry
	err = filepath.Walk(logSaveDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			f := dirEntry{
				path: path,
				info: info,
			}
			files = append(files, f)
		}
		return nil
	})
	unpackLogfiles(logSaveDir, files)
}

// wait time for rate of 125k BYtes * 5 plus 20%
func getSleepDuration(cSize int) time.Duration {
	singleChunkTime := float64(cSize) / (float64(desiredSpeedMbps*1.20) * MbpsToBytes)
	return time.Duration(singleChunkTime * float64(time.Second))
}
