// Copyright (c) 2025 Zededa, Inc.
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
	ansi = "[\u0009\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
)

// getMemlogMsg - goroutine to get messages from memlogd queue
func getMemlogMsg(logChan chan inputEntry, panicFileChan chan []byte) {
	sockName := fmt.Sprintf("/run/%s.sock", "memlogdq")
	s, err := net.Dial("unix", sockName)
	if err != nil {
		log.Fatal("getMemlogMsg: Dial:", err)
	}
	defer s.Close()
	log.Functionf("getMemlogMsg: got socket for memlogdq")

	var writeByte byte = 2
	readTimeout := 30 * time.Second

	// have to write byte value 2 to trigger memlogd queue streaming
	_, err = s.Write([]byte{writeByte})
	if err != nil {
		log.Fatal("getMemlogMsg: write to memlogd failed:", err)
	}

	var panicStackCount int
	bufReader := bufio.NewReader(s)
	for {
		if err = s.SetDeadline(time.Now().Add(readTimeout)); err != nil {
			log.Fatal("getMemlogMsg: SetDeadline:", err)
		}

		bytes, err := bufReader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF && !strings.HasSuffix(err.Error(), "i/o timeout") {
				log.Fatal("getMemlogMsg: bufRead Read:", err)
			}
		}
		if len(bytes) == 0 {
			time.Sleep(5 * time.Second)
			continue
		}
		var pidStr string
		// Everything is json, in some cases with an embedded json Msg
		var logEntry MemlogLogEntry
		if err := json.Unmarshal(bytes, &logEntry); err != nil {
			log.Warnf("Received non-json from memlogd: %s\n",
				string(bytes))
			continue
		}

		// Is the Msg itself json?
		var logInfo Loginfo
		if err := json.Unmarshal([]byte(logEntry.Msg), &logInfo); err == nil {
			// Use the inner JSON struct
			// Go back to the envelope for anything not in the inner JSON
			if logInfo.Time == "" {
				logInfo.Time = logEntry.Time
			}
			if logInfo.Source == "" {
				logInfo.Source = logEntry.Source
			}
			// and keep the original message text and fields
			logInfo.Msg = logEntry.Msg
		} else {
			// Start with the envelope
			logInfo.Source = logEntry.Source
			logInfo.Time = logEntry.Time
			logInfo.Msg = logEntry.Msg

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

		// all logs must have the level field
		if logInfo.Level == "" {
			logInfo.Level = logrus.InfoLevel.String()
		}

		logFromApp := strings.Contains(logInfo.Source, "guest_vm") || logInfo.Containername != ""

		if logFromApp {
			logmetrics.AppMetrics.NumInputEvent++
		} else {
			logmetrics.DevMetrics.NumInputEvent++
		}

		if logInfo.Pid != 0 {
			pidStr = strconv.Itoa(logInfo.Pid)
		}

		// not to upload 'kube' container logs, one can find in /persist/kubelog for detail
		if logInfo.Source == "kube" {
			continue
		}

		sendToRemote := false
		if !logFromApp { // there are no granularity nobs for the edge apps' log levels
			loglevel, err := logrus.ParseLevel(logInfo.Level)
			if err != nil {
				log.Errorf("getMemlogMsg: found invalid log level %s in message from %s", logInfo.Level, logInfo.Source)
			} else {
				// see if we have an agent specific log level
				if remoteLogLevel, ok := agentsRemoteLogLevel.Load(logInfo.Source); ok {
					sendToRemote = loglevel <= remoteLogLevel.(logrus.Level)
				} else {
					sendToRemote = loglevel <= agentDefaultRemoteLogLevel.Load().(logrus.Level)
				}
			}
		}

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

		// if we are in watchdog going down. fsync often
		checkWatchdogRestart(&entry, &panicStackCount, string(bytes), panicFileChan)

		logChan <- entry
	}
}

// Returns level, time and msg if the string contains those attr=val
func parseLevelTimeMsg(content string) (level string, timeStr string, msg string) {
	content = remNonPrintable(content)
	if strings.Contains(content, ",\"msg\":") {
		// Json or something - bail
		return
	}
	level1 := strings.SplitN(content, "level=", 2)
	if len(level1) == 2 {
		level2 := strings.Split(level1[1], " ")
		level = level2[0]
	}
	time1 := strings.SplitN(content, "time=", 2)
	if len(time1) == 2 {
		time2 := strings.Split(time1[1], "\"")
		if len(time2) == 3 {
			timeStr = time2[1]
		}
	}
	msg1 := strings.SplitN(content, "msg=", 2)
	if len(msg1) == 2 {
		msg2 := strings.Split(msg1[1], "\"")
		if len(msg2) == 3 {
			msg = msg2[1]
		}
	}
	return
}

func remNonPrintable(str string) string {
	var re = regexp.MustCompile(ansi)
	myStr := re.ReplaceAllString(str, "")
	myStr = strings.Trim(myStr, "\r")
	return strings.Trim(myStr, "\n")
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
