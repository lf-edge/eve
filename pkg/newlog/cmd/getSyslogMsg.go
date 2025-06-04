// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// getSyslogMsg - go routine to handle syslog input
func getSyslogMsg(loggerChan chan inputEntry) {

	sysfmt := regexp.MustCompile("<([0-9]+)>(.{15}|.{25}) (.*?): (.*)")
	conn, err := listenDevLog()
	if err != nil {
		log.Error(err)
		return
	}

	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			log.Error(err)
			return
		}

		entry, err := newMessage(buf, n, sysfmt)
		if err != nil {
			log.Error(err)
			continue
		}
		if suppressMsg(entry, atomic.LoadUint32(&syslogPrio)) {
			continue
		}

		entry.sendToRemote = types.SyslogKernelLogLevelNum[entry.severity] <= atomic.LoadUint32(&syslogRemotePrio)

		logmetrics.NumSyslogMessages++
		logmetrics.DevMetrics.NumInputEvent++
		log.Tracef("getSyslogMsg (%d) entry msg %s", logmetrics.NumSyslogMessages, entry.content)

		loggerChan <- entry
	}
}

// listenDevLog() - substitute /dev/log with our AF_UNIX socket and open it
//
//	for listening
func listenDevLog() (*net.UnixConn, error) {
	UnixPath := "/dev/log"
	os.Remove(UnixPath)
	a, err := net.ResolveUnixAddr("unixgram", UnixPath)
	if err != nil {
		return nil, err
	}
	unix, err := net.ListenUnixgram("unixgram", a)
	if err != nil {
		return nil, err
	}
	err = os.Chmod(UnixPath, 0666)
	if err != nil {
		return nil, err
	}

	return unix, nil
}

func newMessage(pkt []byte, size int, sysfmt *regexp.Regexp) (inputEntry, error) {
	entry := inputEntry{}
	res := sysfmt.FindSubmatch(pkt)
	if len(res) != 5 {
		return entry, fmt.Errorf("can't parse: %d %s", len(res), string(pkt))
	}

	var tagpid, msgTag, msgPriority, msgPid string
	var msgRaw []byte

	msgReceived := time.Now()
	p, _ := strconv.ParseInt(string(res[1]), 10, 64)
	msgPriority = types.SyslogKernelLogLevelStr[p%8]
	misc := res[3]
	// Check for either "hostname tagpid" or "tagpid"
	a := bytes.SplitN(misc, []byte(" "), 2)
	if len(a) == 2 {
		tagpid = string(a[1])
	} else {
		//msg.Hostname = hostname
		tagpid = string(a[0])
	}

	// tagpid is either "tag[pid]" or "[pid]" or just "tag".
	if n := strings.Index(tagpid, "["); n > 0 || strings.HasPrefix(tagpid, "[") && strings.HasSuffix(tagpid, "]") {
		msgPid = tagpid[n+1 : (len(tagpid) - 1)]
		msgTag = tagpid[:n]
	} else {
		msgTag = tagpid
	}

	// Raw message string excluding priority, timestamp, tag and pid.
	n := bytes.Index(pkt, []byte("]: "))
	if n > 0 {
		if size > n+2 {
			msgRaw = bytes.TrimSpace(pkt[n+2 : size])
		} else {
			msgRaw = bytes.TrimSpace(pkt[n+2:])
		}
	} else {
		n = bytes.Index(pkt, []byte(": "))
		if n > 0 {
			if size > n+1 {
				msgRaw = bytes.TrimSpace(pkt[n+1 : size])
			} else {
				msgRaw = bytes.TrimSpace(pkt[n+1:])
			}
		} else {
			msgRaw = bytes.TrimSpace(pkt)
		}
	}

	entry = inputEntry{
		source:    msgTag,
		severity:  msgPriority,
		content:   string(msgRaw),
		pid:       msgPid,
		timestamp: msgReceived.Format(time.RFC3339Nano),
	}

	return entry, nil
}
