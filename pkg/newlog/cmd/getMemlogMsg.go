// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	ansi = "(?:\u001B|\\\\u001[bB])\\[[0-9;]*[A-Za-z]|(?:\u001B|\\\\u001[bB])[\\(\\)\\[\\]#;?]*[A-Za-z0-9]|(?:\u009B|\\\\u009[bB])[0-9;]*[A-Za-z]"
)

const (
	// panicQuietPeriod is how long the capture waits for more traceback lines
	// before writing the panic files.
	panicQuietPeriod = 2 * time.Second
)

var (
	memlogdSocket = "/run/memlogdq.sock"

	// Budget for one capture, kept in variables so tests can shrink it. zedbox
	// dumps every goroutine as one memlogd record per line, which runs to
	// thousands of records and hundreds of KiB, and the frames that explain a
	// crash are rarely the first ones.
	maxPanicRecords = 20000
	maxPanicBufSize = 2 << 20

	// Prefixes of the first stderr line of a fatal pillar failure. Signal
	// banners appear both bare ("SIGABRT: abort") and inside a Go panic
	// message ("[signal SIGSEGV: segmentation violation ...").
	panicStartMarkers = []string{
		"panic:",
		"fatal error:",
		"ASSERT at ",
		"[signal SIG",
		"SIGABRT:",
		"SIGSEGV:",
		"SIGBUS:",
		"SIGFPE:",
		"SIGILL:",
		"SIGTRAP:",
		"signal arrived during cgo execution",
	}
)

// getMemlogMsg - goroutine to get messages from memlogd queue
func getMemlogMsg(logChan chan inputEntry, panicFileChan chan []byte) {
	s, err := net.Dial("unix", memlogdSocket)
	if err != nil {
		log.Fatal("getMemlogMsg: Dial:", err)
	}
	defer s.Close()
	log.Functionf("getMemlogMsg: got socket for memlogdq")

	processMemlogStream(s, logChan, panicFileChan)
}

// processMemlogStream processes the memlogd stream from the provided connection.
// This function is extracted to enable better testing.
func processMemlogStream(conn net.Conn, logChan chan inputEntry, panicFileChan chan []byte) {
	var writeByte byte = 2
	readTimeout := 30 * time.Second

	// have to write byte value 2 to trigger memlogd queue streaming
	_, err := conn.Write([]byte{writeByte})
	if err != nil {
		log.Fatal("processMemlogStream: write to memlogd failed:", err)
	}

	var panicStackCount int
	bufReader := bufio.NewReader(conn)
	for {
		if err = conn.SetDeadline(time.Now().Add(readTimeout)); err != nil {
			log.Fatal("processMemlogStream: SetDeadline:", err)
		}

		bytes, err := bufReader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF && !strings.HasSuffix(err.Error(), "i/o timeout") {
				log.Fatal("processMemlogStream: bufRead Read:", err)
			}
		}
		if len(bytes) == 0 {
			time.Sleep(5 * time.Second)
			continue
		}

		// Parse and convert the memlog entry
		entry, err := parseMemlogEntry(bytes)
		if err != nil {
			log.Warn(err)
			continue
		} else if entry == (inputEntry{}) {
			continue
		}

		// if we are in watchdog going down. fsync often
		checkWatchdogRestart(&entry, &panicStackCount, panicFileChan)

		logChan <- entry
	}
}

// parseMemlogEntry parses a raw memlogd entry and converts it to an inputEntry.
// Returns the parsed entry and any error encountered during parsing.
func parseMemlogEntry(rawBytes []byte) (inputEntry, error) {
	var logEntry MemlogLogEntry
	if err := json.Unmarshal(rawBytes, &logEntry); err != nil {
		return inputEntry{}, fmt.Errorf("received non-json from memlogd: %s", string(rawBytes))
	}

	// Parse the log info from the memlog entry
	logInfo := parseLogInfo(logEntry)

	// don't process kube logs, since they are handled separately in /persist/kubelog
	if logInfo.Source == "kube" || logInfo.Source == "kube.out" {
		return inputEntry{}, nil
	}

	// all logs must have the level field
	if logInfo.Level == "" {
		logInfo.Level = logrus.InfoLevel.String()
	}

	logFromApp := isAppLog(logInfo)

	// Update metrics
	if logFromApp {
		logmetrics.AppMetrics.NumInputEvent++
	} else {
		logmetrics.DevMetrics.NumInputEvent++
	}

	var pidStr string
	if logInfo.Pid != 0 {
		pidStr = strconv.Itoa(logInfo.Pid)
	}

	sendToRemote := shouldSendToRemote(logInfo, logFromApp)

	entry := inputEntry{
		source:       logInfo.Source,
		content:      logInfo.Msg,
		pid:          pidStr,
		timestamp:    logInfo.Time,
		function:     logInfo.Function,
		filename:     logInfo.Filename,
		severity:     logInfo.Level,
		appUUID:      logInfo.Appuuid,
		acName:       logInfo.Containername,
		acLogTime:    logInfo.Eventtime,
		sendToRemote: sendToRemote,
	}

	return entry, nil
}

// parseLogInfo extracts structured log information from a MemlogLogEntry.
// It handles different log formats including JSON, key=value pairs, and plain text.
func parseLogInfo(memlogEntry MemlogLogEntry) Loginfo {
	var logInfo Loginfo
	// Start with the envelope - if there is no additional info inside msg, then just use the envelope info
	logInfo.Source = memlogEntry.Source
	logInfo.Time = memlogEntry.Time
	logInfo.Msg = memlogEntry.Msg

	switch memlogEntry.Source {
	// most logs coming from our services have one of these three formats:
	// 1. JSON with logrus fields
	// 2. key=value pairs (logrus's standard text format)
	// 3. plain text (watchdog, debug and other non-go services as well as guest_vm)
	// We handle those three cases in the default case below
	// Some services use other logging libraries and formats and need to be added
	// as exceptions to ensure proper handling. Those are added as special cases:
	case "vector", "vector.err", "vector.out":
		// These messages come from vector in different format
		// Treat them as plain text for now
		// (Vector's JSON format doesn't produce valid JSON (key collision), so we're not using it)

	default:
		cleanMsg := cleanForLogParsing(memlogEntry.Msg)
		// These messages come from golang's logrus package
		if err := json.Unmarshal([]byte(cleanMsg), &logInfo); err == nil {
			// Use the inner JSON struct
			// Go back to the envelope for anything not in the inner JSON
			if logInfo.Time == "" {
				logInfo.Time = memlogEntry.Time
			}
			if logInfo.Source == "" {
				logInfo.Source = memlogEntry.Source
			}
			// and keep the cleaned message text and fields
			logInfo.Msg = cleanMsg
		} else {
			// Some messages have attr=val syntax
			// If the inner message has Level, Time or Msg set they take
			// precedence over the envelope
			level, timeStr, msg := parseLevelTimeMsg(memlogEntry.Msg)
			if level != "" {
				logInfo.Level = level
			}
			if timeStr != "" {
				logInfo.Time = timeStr
			}
			if msg != "" {
				logInfo.Msg = msg
			}
		}
	}

	return logInfo
}

// isAppLog determines if a log entry is from an application (as opposed to device/system).
func isAppLog(logInfo Loginfo) bool {
	return strings.Contains(logInfo.Source, "guest_vm") || logInfo.Containername != ""
}

// shouldSendToRemote determines if a log should be sent to the remote endpoint
// based on the configured log levels.
func shouldSendToRemote(logInfo Loginfo, logFromApp bool) bool {
	if logFromApp {
		// there are no granularity knobs for the edge apps' log levels
		return false
	}

	loglevel, err := logrus.ParseLevel(logInfo.Level)
	if err != nil {
		log.Errorf("shouldSendToRemote: found invalid log level %s in message from %s",
			logInfo.Level, logInfo.Source)
		return false
	}

	// see if we have an agent specific log level
	if remoteLogLevel, ok := agentsRemoteLogLevel.Load(logInfo.Source); ok {
		return loglevel <= remoteLogLevel.(logrus.Level)
	}
	return loglevel <= agentDefaultRemoteLogLevel.Load().(logrus.Level)
}

// Returns level, time and msg if the string contains those attr=val
func parseLevelTimeMsg(content string) (level string, timeStr string, msg string) {
	content = cleanForLogParsing(content)
	if strings.Contains(content, ",\"msg\":") {
		// Json or something - bail
		return
	}
	level1 := strings.SplitN(content, "level=", 2)
	if len(level1) == 2 {
		level2 := strings.Split(level1[1], " ")
		level = strings.ToLower(level2[0])
	}
	time1 := strings.SplitN(content, "time=", 2)
	if len(time1) == 2 && strings.HasPrefix(time1[1], "\"") {
		time2 := strings.Split(time1[1], "\"")
		if len(time2) >= 3 {
			timeStr = time2[1]
		}
	}
	msg1 := strings.SplitN(content, "msg=", 2)
	if len(msg1) == 2 && strings.HasPrefix(msg1[1], "\"") {
		msg2 := strings.Split(msg1[1], "\"")
		if len(msg2) >= 3 {
			msg = msg2[1]
		}
	}
	return
}

func cleanForLogParsing(str string) string {
	// Remove ANSI escape sequences (colors, cursor movement, etc.)
	var re = regexp.MustCompile(ansi)
	cleaned := re.ReplaceAllString(str, "")

	// Remove leading/trailing whitespace that interferes with parsing
	cleaned = strings.Trim(cleaned, "\r\n")

	return cleaned
}

// flush more often when we are going down by reading from watchdog log message itself
func checkWatchdogRestart(entry *inputEntry, panicStackCount *int, panicFileChan chan []byte) {
	// source can be watchdog or watchdog.err
	if strings.HasPrefix(entry.source, "watchdog") {
		if strings.Contains(entry.content, "Retry timed-out at") {
			entry.severity = "emerg"
			syncToFileCnt = 1

			// in case if the system does not go down, fire a timer to reset it to normal sync count
			schedResetTimer = time.NewTimer(300 * time.Second)
		}
		return
	}

	// the panic generated message can have the source either as 'pillar' or 'pillar.out'
	if !strings.Contains(entry.source, "pillar") {
		return
	}

	panicBufLock.Lock()
	defer panicBufLock.Unlock()

	if *panicStackCount == 0 {
		if !isPanicStart(entry.content) ||
			strings.Contains(entry.content, "rebootReason") {
			return
		}
		*panicStackCount = 1
		appendPanicLine(entry.content)
		panicWriteTimer.Reset(panicQuietPeriod)
		return
	}

	*panicStackCount++
	appendPanicLine(entry.content)

	// A traceback arrives as a burst of one record per line and other services
	// keep logging in between, so the capture ends on a quiet period rather
	// than on the first record from another source. The budget only bounds how
	// much of a dying process's stack is kept.
	if *panicStackCount >= maxPanicRecords || len(panicBuf) >= maxPanicBufSize {
		panicWriteTimer.Stop()
		*panicStackCount = 0
		panicFileChan <- panicBuf
		panicBuf = nil
		return
	}
	panicWriteTimer.Reset(panicQuietPeriod)
}

// appendPanicLine adds one traceback line to panicBuf. Caller must hold
// panicBufLock.
func appendPanicLine(content string) {
	panicBuf = append(panicBuf, content...)
	panicBuf = append(panicBuf, '\n')
}

// isPanicStart reports whether a pillar stderr line begins a fatal failure.
// Go panics and runtime throws print "panic:"/"fatal error:", while a C
// assertion or fatal signal raised under cgo runs no Go panic machinery at all
// and prints only the assert text followed by a signal banner.
func isPanicStart(content string) bool {
	content = strings.TrimLeft(content, " \t")
	for _, marker := range panicStartMarkers {
		if strings.HasPrefix(content, marker) {
			return true
		}
	}
	return false
}

// MemlogLogEntry is copied from memlogd; maybe it should provide a parser
// which sends this struct on a channel.
type MemlogLogEntry struct {
	Time   string `json:"time"`
	Source string `json:"source"`
	Msg    string `json:"msg"`
}

// Loginfo represents the standard log entry format for pillar agents
type Loginfo struct {
	Level         string `json:"level"`
	Time          string `json:"time"` // RFC3339 with Nanoseconds
	Msg           string `json:"msg"`
	Pid           int    `json:"pid"`
	Function      string `json:"func"`
	Filename      string `json:"file"`
	Source        string `json:"source"`
	Appuuid       string `json:"appuuid"`
	Containername string `json:"containername"`
	Eventtime     string `json:"eventtime"`
}
