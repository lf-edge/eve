// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"

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
