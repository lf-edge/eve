// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lf-edge/eve-api/go/logs"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

// for dev, returns the meta data, and for app, return the appName
func formatAndGetMeta(appuuid string) string {
	if appuuid != "" {
		// for App, just the appName info
		val, found := domainUUID.Load(appuuid)
		if found {
			appD := val.(appDomain)
			return appD.appName
		}
	}
	metaStr := logs.LogBundle{
		DevID:      devMetaData.uuid,
		Image:      devMetaData.curPart,
		EveVersion: devMetaData.imageVer,
	}
	mapJmeta, _ := json.Marshal(&metaStr)
	return string(mapJmeta)
}

func suppressMsg(entry inputEntry, cfgPrio uint32) bool {
	pri := parseSyslogLogLevel(entry.severity)

	return pri > cfgPrio
}

// parse log level string
func parseSyslogLogLevel(loglevel string) uint32 {
	prio, ok := types.SyslogKernelLogLevelNum[loglevel]
	if !ok {
		prio = types.SyslogKernelLogLevelNum[types.SyslogKernelDefaultLogLevel]
	}

	return prio
}

// sanitizeGzipHeader rewrites s so it is safe to assign to gzip.Writer.Name
// or gzip.Writer.Comment. RFC 1952 restricts those fields to ISO-8859-1
// with no NUL byte; Go's gzip writer enforces this and returns
// "gzip.Write: non-Latin-1 header string" from Close() otherwise, which
// is fatal in newlogd's compression path. Each disallowed rune is
// replaced with a Go-style \uXXXX / \UXXXXXXXX escape so the original
// value is recoverable downstream. Latin-1 runes (including accented
// characters in 0x80-0xFF) pass through unchanged.
func sanitizeGzipHeader(s string) string {
	safe := true
	for _, r := range s {
		if r == 0 || r > 0xff {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == 0:
			b.WriteString(`\u0000`)
		case r > 0xffff:
			fmt.Fprintf(&b, `\U%08x`, r)
		case r > 0xff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func parseAgentLogLevel(loglevel string) logrus.Level {
	switch loglevel {
	case "none":
		// TODO: this should suppress most logs, but needs to be later replaced with a better solution
		return logrus.PanicLevel
	case "all":
		return logrus.TraceLevel
	default:
		level, err := logrus.ParseLevel(loglevel)
		if err != nil {
			log.Errorf("parseAgentLogLevel: invalid log level %s for %s", loglevel, agentName)
		}
		return level
	}
}
