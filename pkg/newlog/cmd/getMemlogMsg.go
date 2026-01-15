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
	ansi = "\u001B\\[[0-9;]*[A-Za-z]|\u001B[\\(\\)\\[\\]#;?]*[A-Za-z0-9]|\u009B[0-9;]*[A-Za-z]"
)

var (
	memlogdSocket = "/run/memlogdq.sock"
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
		checkWatchdogRestart(&entry, &panicStackCount, string(bytes), panicFileChan)

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
	if logInfo.Source == "kube" {
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
func parseLogInfo(logEntry MemlogLogEntry) Loginfo {
	var logInfo Loginfo
	// Start with the envelope - if there is no additional info inside msg, then just use the envelope info
	logInfo.Source = logEntry.Source
	logInfo.Time = logEntry.Time
	logInfo.Msg = logEntry.Msg

	switch logEntry.Source {
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
		// These messages come from golang's logrus package
		if err := json.Unmarshal([]byte(logEntry.Msg), &logInfo); err == nil {
			// Use the inner JSON struct
			// Go back to the envelope for anything not in the inner JSON
			if logInfo.Time == "" {
				logInfo.Time = logEntry.Time
			}
			if logInfo.Source == "" {
				logInfo.Source = logEntry.Source
			}
			// Clean ANSI codes from the inner msg, then rebuild JSON string
			cleanMsg := cleanForLogParsing(logInfo.Msg)
			tempLogInfo := struct {
				Appuuid       string `json:"appuuid,omitempty"`
				Containername string `json:"containername,omitempty"`
				Level         string `json:"level,omitempty"`
				Msg           string `json:"msg"`
				Time          string `json:"time,omitempty"`
			}{
				Appuuid:       logInfo.Appuuid,
				Containername: logInfo.Containername,
				Level:         logInfo.Level,
				Msg:           cleanMsg,
				Time:          logInfo.Time,
			}
			if jsonBytes, err := json.Marshal(tempLogInfo); err == nil {
				logInfo.Msg = string(jsonBytes)
			} else {
				logInfo.Msg = logEntry.Msg
			}
		} else {
			// Some messages have attr=val syntax
			// If the inner message has Level, Time or Msg set they take
			// precedence over the envelope
			level, timeStr, msg := parseLevelTimeMsg(logEntry.Msg)
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
func checkWatchdogRestart(entry *inputEntry, panicStackCount *int, origMsg string, panicFileChan chan []byte) {
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
	// this origMsg is the raw message, the ";" is the deliminator between source and content.
	if strings.Contains(entry.source, "pillar") && strings.Contains(origMsg, ";panic:") &&
		!strings.Contains(entry.content, "rebootReason") {
		*panicStackCount = 1
		panicBuf = append(panicBuf, []byte(origMsg)...)
		// in case there is only few log messages after this, kick off a timer to write the panic files
		panicWriteTimer = time.NewTimer(2 * time.Second)
	} else if *panicStackCount > 0 {
		var done bool
		if strings.Contains(entry.source, "pillar") {
			panicBuf = append(panicBuf, []byte(origMsg)...)
		} else {
			// conclude the capture when log source is not 'pillar'
			done = true
		}

		*panicStackCount++

		if *panicStackCount > 15 || done {
			panicWriteTimer.Stop()
			*panicStackCount = 0
			panicFileChan <- panicBuf
			panicBuf = nil
		}
	}
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
