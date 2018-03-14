// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package main

import (
	"bufio"
	"flag"
	"fmt"
	//"github.com/zededa/api/zmet"
	"github.com/zededa/go-provision/watch"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

const (
	defaultLogdirname = "/var/log"
)

var debug bool

// global stuff
type logDirModifyHandler func(ctx *loggerContext, logFileName string, source string)
type logDirDeleteHandler func(ctx *loggerContext, logFileName string, source string)

// Set from Makefile
var Version = "No version specified"

// Based on the proto file
type logEntry struct {
	severity  string
	source    string // basename of filename?
	image     string // XXX missing in zlog.proto
	iid       string // XXX e.g. PID - where do we get it from?
	content   string // One line
	timestamp time.Time
}

// List of log files we watch
type loggerContext struct {
	logfileReaders []logfileReader
	logChan        chan<- logEntry
}

type logfileReader struct {
	filename string
	source   string
	fileDesc *os.File
	reader   *bufio.Reader
	size     int64 // To detect file truncation
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug")
	logdirPtr := flag.String("l", defaultLogdirname, "Log file directory")
	flag.Parse()
	debug = *debugPtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	logDirName := *logdirPtr
	log.Printf("Starting log manager... watching %s\n", logDirName)

	loggerChan := make(chan logEntry)
	ctx := loggerContext{logChan: loggerChan}
	// Start sender of log events
	// XXX or we run this in main routine and the logDirChanges loop
	// in a go routine??
	go processEvents(loggerChan)

	// XXX The OtherPartition files will not change hence we can just
	// read them and send their lines; no need to watch for changes.
	// Should we read all of them serially?

	logDirChanges := make(chan string)
	go watch.WatchStatus(logDirName, logDirChanges)
	log.Println("called watcher...")
	for {
		select {
		case change := <-logDirChanges:
			HandleLogDirEvent(change, logDirName, &ctx,
				handleLogDirModify, handleLogDirDelete)
		}
	}
}

// This runs as a separate go routine sending out data

func processEvents(logChan <-chan logEntry) {
	for {
		select {
		case event := <-logChan:
			HandleLogEvent(event)
		}
	}
}

var msgIdCounter = 1

func HandleLogEvent(event logEntry) {
	// Assign a unique msgId for each message
	msgId := msgIdCounter
	msgIdCounter += 1
	// XXX send message over protobuf
	fmt.Printf("Read event from %s time %v id %d: %s\n",
		event.source, event.timestamp, msgId, event.content)
}

func HandleLogDirEvent(change string, logDirName string, ctx *loggerContext,
	handleLogDirModifyFunc logDirModifyHandler, handleLogDirDeleteFunc logDirDeleteHandler) {

	operation := string(change[0])
	fileName := string(change[2:])
	if !strings.HasSuffix(fileName, ".log") {
		log.Printf("Ignoring file <%s> operation %s\n",
			fileName, operation)
		return
	}
	logFilePath := logDirName + "/" + fileName
	// Remove .log from name */
	name := strings.Split(fileName, ".log")
	source := name[0]
	if operation == "D" {
		handleLogDirDeleteFunc(ctx, logFilePath, source)
		return
	}
	if operation != "M" {
		log.Fatal("Unknown operation from Watcher: ",
			operation)
	}
	handleLogDirModifyFunc(ctx, logFilePath, source)
}

// If the filename is new we spawn a go routine which will read
func handleLogDirModify(ctx *loggerContext, filename string, source string) {
	for i, r := range ctx.logfileReaders {
		if r.filename == filename {
			readLineToEvent(&ctx.logfileReaders[i], ctx.logChan)
			return
		}
	}
	log.Printf("handleLogDirModify: add %s, source %s\n", filename, source)
	fileDesc, err := os.Open(filename)
	if err != nil {
		log.Printf("Log file ignored due to %s\n", err)
		return
	}
	// Start reading from the file with a reader.
	reader := bufio.NewReader(fileDesc)
	if reader == nil {
		log.Printf("Log file ignored due to %s\n", err)
		return
	}
	r := logfileReader{filename: filename,
		source:   source,
		fileDesc: fileDesc,
		reader:   reader,
	}
	// read initial entries until EOF
	readLineToEvent(&r, ctx.logChan)
	ctx.logfileReaders = append(ctx.logfileReaders, r)
}

// XXX TBD should we stop the go routine?
func handleLogDirDelete(ctx *loggerContext, filename string, source string) {
}

// Read until EOF or error
func readLineToEvent(r *logfileReader, logChan chan<- logEntry) {
	// Check if shrunk aka truncated
	fi, err := r.fileDesc.Stat()
	if err != nil {
		log.Printf("Stat failed %s\n", err)
		return
	}
	if fi.Size() < r.size {
		log.Printf("File shrunk from %d to %d\n", r.size, fi.Size())
		_, err = r.fileDesc.Seek(0, os.SEEK_SET)
		if err != nil {
			log.Printf("Seek failed %s\n", err)
			return
		}
	}
	for {
		line, err := r.reader.ReadString('\n')
		if err != nil {
			// XXX do we need to look for truncatation during
			// this loop?
			if debug {
				log.Println(err)
			}
			if err != io.EOF {
				fmt.Printf(" > Failed!: %v\n", err)
			}
			break
		}
		// XXX remove trailing "/n" from line
		// XXX parse timestamp and remove it from line (if present)
		// otherwise leave timestamp unitialized
		logChan <- logEntry{source: r.source, content: line}
	}
	// Update size
	fi, err = r.fileDesc.Stat()
	if err != nil {
		log.Printf("Stat failed %s\n", err)
		return
	}
	r.size = fi.Size()
}

// XXX useful to read unchanging files until EOF
// Use for the otherpartition files!
func logReader(logFile string, source string, logChan chan<- logEntry) {
	fileDesc, err := os.Open(logFile)
	if err != nil {
		log.Printf("Log file ignored due to %s\n", err)
		return
	}
	// Start reading from the file with a reader.
	reader := bufio.NewReader(fileDesc)
	if reader == nil {
		log.Printf("Log file ignored due to %s\n", err)
		return
	}
	r := logfileReader{filename: logFile,
		source:   source,
		fileDesc: fileDesc,
		reader:   reader,
	}
	// read entries until EOF
	readLineToEvent(&r, logChan)
	log.Printf("logReader done for %s\n", logFile)
}
