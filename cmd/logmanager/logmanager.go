// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package main

import (
	"bufio"
	"flag"
	"fmt"
//	"github.com/zededa/api/zmet"
	"github.com/zededa/go-provision/watch"
	"io"
	"log"
	"os"
	"strings"
	//"time"
)

const (
	logDirName = "/var/log"
)

var debug bool
var logContentChan chan string
var logFileChan chan string

// global stuff
var logFileSizeMap map[string]int64

type logReadHandler func(logFileName string, logContent string)
type logDeleteHandler func(logFileName string)

// Set from Makefile
var Version = "No version specified"

func main() {

	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug")
	flag.Parse()
	debug = *debugPtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}

	log.Println("Starting log manager...")
	logContentChan = make(chan string)
	logFileChan = make(chan string)
	go sendLogsOnChannel(logContentChan, logFileChan)

	if logFileSizeMap == nil {
		log.Println("Creating logFileSizeMap map")
		logFileSizeMap = make(map[string]int64)
	}

	logChanges := make(chan string)
	go watch.WatchStatus(logDirName, logChanges)
	log.Println("called watcher...")
	for {
		select {
		case change := <-logChanges:
			{
				log.Println("change: ", change)
				HandleLogEvent(change, logDirName, handleLogModify, handleLogDelete)
			}
		}
	}
}

func HandleLogEvent(change string, logDirName string, handleLogModifyFunc logReadHandler, handleLogDeleteFunc logDeleteHandler) {

	operation := string(change[0])
	fileName := string(change[2:])
	if !strings.HasSuffix(fileName, ".log") {
		log.Printf("Ignoring file <%s> operation %s\n",
			fileName, operation)
		return
	}
	// Remove .log from name */
	name := strings.Split(fileName, ".log")
	logFileName := name[0]
	if operation == "D" {
		handleLogDeleteFunc(name[0])
		return
	}
	if operation != "M" {
		log.Fatal("Unknown operation from Watcher: ",
			operation)
	}
	logFilePath := logDirName + "/" + fileName
	go readLogFileLineByLine(logFilePath, logFileName, handleLogModifyFunc)

}

func readLogFileLineByLine(logFilePath, fileName string, handleLogModifyFunc logReadHandler) {

	logFile := logFilePath
	fileDesc, err := os.Open(logFile)

	if err != nil {
		log.Fatalf("%v for %s\n", err, logFile)
	}
	defer fileDesc.Close()

	fileSize, err := fileDesc.Stat()
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("size of file: ", fileSize.Size())
	//logFileSizeMap[logFile] = fileSize.Size()

	if logFileSizeMap != nil {
		for fileName, fileSize := range logFileSizeMap {
			if fileName == logFile {
				_, err := fileDesc.Seek(fileSize, 0)
				if err != nil {
					log.Println(err)
				}
			}
		}
	}
	// Start reading from the file with a reader.
	reader := bufio.NewReader(fileDesc)
	if reader == nil {
		log.Fatalf("%s, reader create failed\n", logFile)
	}

	/*reader := getLoggerReader(logFile)
	if reader == nil {
		log.Fatalf("%s, log File open failed\n", logFile)
	}*/

	for {
		line, err := reader.ReadString('\n')

		if err != nil {
			if debug {
				log.Println(err)
			}
			if err != io.EOF {
				fmt.Printf(" > Failed!: %v\n", err)
			}
			break
		}
		handleLogModifyFunc(fileName, line)
	}
	logFileSizeMap[logFile] = fileSize.Size()
}

func handleLogModify(logFilename string, logContent string) {
	//if debug {
	//log.Printf("handleLogModify for %s\n", logFilename)
	//log.Println("value of log content: ", logContent)
	//}
	contentAndFileName := logContent + " -logFileName- " + logFilename
	logContentChan <- contentAndFileName
	logFileChan <- logFilename
}

func handleLogDelete(logFilename string) {
	//if debug {
	log.Printf("handleLogDelete for %s\n", logFilename)
	//}

}
func sendLogsOnChannel(logContent chan string, logFileName chan string) {
	log.Println("protoStrForLogs called...")

	for {
		select {
		case content := <-logContentChan:
			log.Printf("logContentChan %s\n", content)
			makeAndsendProtoStrForLogsToZedcloud(content)
		//case filename := <-logFileChan:
		//log.Println("logFileChann: ", filename)

		default:
		}
	}
}
func makeAndsendProtoStrForLogsToZedcloud(content string) {
//	var ReportLogs = &zmet.LogBundle{}
}
