// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package main
import (
	"github.com/zededa/go-provision/watch"
	"log"
	"flag"
	"os"
	"strings"
	"bufio"
	"fmt"
	"io"
)

const (
	logDirName = "/var/log"
)

// Set from Makefile
var Version = "No version specified"

func main() {

	log.SetOutput(os.Stdout)
    log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
    versionPtr := flag.Bool("v", false, "Version")
    //debugPtr := flag.Bool("d", false, "Debug")
    flag.Parse()
    //debug = *debugPtr
    if *versionPtr {
        fmt.Printf("%s: %s\n", os.Args[0], Version)
        return
    }
	log.Println("Starting log manager...")
	logChanges := make(chan string)
	go watch.WatchStatus(logDirName, logChanges)
	log.Println("called watcher...")
	for {
		select {
		case change := <-logChanges:
			{
				//log.Println("change: ", change)
				HandleLogEvent(change, logDirName, handleLogModify, handleLogDelete)
			}
		}
	}
}

type logReadHandler func(logFileName string, logContent string)
type logDeleteHandler func(logFileName string)

func HandleLogEvent(change string, logDirName string, handleLogModifyFunc logReadHandler, handleLogDeleteFunc logDeleteHandler) {
	operation := string(change[0])
	fileName := string(change[2:])
	if operation == "R" {
		log.Printf("Received restart <%s>; ignored\n", fileName)
		return
	}
	if !strings.HasSuffix(fileName, ".log") {
		log.Printf("Ignoring file <%s> operation %s\n",
			fileName, operation)
		return
	}
	// Remove .log from name */
	name := strings.Split(fileName, ".log")
	if operation == "D" {
		handleLogDeleteFunc(name[0])
		return
	}
	if operation != "M" {
		log.Fatal("Unknown operation from Watcher: ",
			operation)
	}
	logFile := logDirName + "/" + fileName

	file, err := os.Open(logFile)

	if err != nil {
		log.Println(err)
	}
	// Start reading from the file with a reader.
	reader := bufio.NewReader(file)

	var line string
	for {
		line, err = reader.ReadString('\n')

		if err != nil {
			log.Println(err)
			break
		}
		handleLogModifyFunc(name[0], line)
	}

	if err != io.EOF {
		fmt.Printf(" > Failed!: %v\n", err)
	}
}

func handleLogModify(logFilename string, logContent string) {

	log.Printf("handleLogModify for %s\n", logFilename)
	log.Println("value of log content: ", logContent)
}

func handleLogDelete(logFilename string) {
	log.Printf("handleLogDelete for %s\n", logFilename)

}
