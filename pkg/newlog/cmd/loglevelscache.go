// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path"

	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

// logLevelsCacheFilename is the name of the file caching the log levels of
// the most recently received global config. zedagent publishes the live
// ConfigItemValueMap only in memory and starts long after newlogd, so
// without this cache all logs produced between boot and the first
// publication would be handled with the default log levels; in particular
// they would be marked for upload to the controller even when remote
// logging is configured off.
//
// Deliberately only the log levels are written to disk, not the whole
// ConfigItemValueMap: the latter may contain sensitive values that must
// not be persisted in cleartext.
const logLevelsCacheFilename = "logLevelsCache.json"

// logLevelsCacheFile is a variable so that tests can redirect it.
var logLevelsCacheFile = path.Join(types.NewlogDir, logLevelsCacheFilename)

// logLevelsCacheSchema is the schema version of the cache file. Bump it
// when the format changes incompatibly; a cache with a different schema
// version is discarded.
const logLevelsCacheSchema = 1

// cachedLogLevels are the log levels that newlogd applies from the global
// config.
type cachedLogLevels struct {
	SchemaVersion int `json:"schemaVersion"`

	// LogLevel is newlogd's own local log level (debug.newlogd.loglevel,
	// falling back to debug.default.loglevel).
	LogLevel string `json:"logLevel"`
	// DefaultRemoteLogLevel is debug.default.remote.loglevel,
	// AgentRemoteLogLevels are the resolved per-agent remote log levels.
	DefaultRemoteLogLevel string            `json:"defaultRemoteLogLevel"`
	AgentRemoteLogLevels  map[string]string `json:"agentRemoteLogLevels"`
	// Local and remote syslog and kernel log levels.
	SyslogLogLevel       string `json:"syslogLogLevel"`
	KernelLogLevel       string `json:"kernelLogLevel"`
	SyslogRemoteLogLevel string `json:"syslogRemoteLogLevel"`
	KernelRemoteLogLevel string `json:"kernelRemoteLogLevel"`
}

// logLevelsFromGlobalConfig extracts the newlogd-relevant log levels from
// the given global config.
func logLevelsFromGlobalConfig(gcp *types.ConfigItemValueMap) *cachedLogLevels {
	loglevel := gcp.AgentSettingStringValue(agentName, types.LogLevel)
	if loglevel == "" {
		loglevel = gcp.GlobalValueString(types.DefaultLogLevel)
	}

	agentLevels := make(map[string]string)
	for agent := range gcp.AgentSettings {
		agentLevels[agent] = getRemoteLogLevelImpl(gcp, agent)
	}

	return &cachedLogLevels{
		SchemaVersion:         logLevelsCacheSchema,
		LogLevel:              loglevel,
		DefaultRemoteLogLevel: gcp.GlobalValueString(types.DefaultRemoteLogLevel),
		AgentRemoteLogLevels:  agentLevels,
		SyslogLogLevel:        gcp.GlobalValueString(types.SyslogLogLevel),
		KernelLogLevel:        gcp.GlobalValueString(types.KernelLogLevel),
		SyslogRemoteLogLevel:  gcp.GlobalValueString(types.SyslogRemoteLogLevel),
		KernelRemoteLogLevel:  gcp.GlobalValueString(types.KernelRemoteLogLevel),
	}
}

// saveLogLevelsCache atomically writes the given log levels to the cache
// file, unless the file already has the same content.
func saveLogLevelsCache(levels *cachedLogLevels) {
	data, err := json.Marshal(levels)
	if err != nil {
		log.Errorf("saveLogLevelsCache: marshal failed: %v", err)
		return
	}
	if current, err := os.ReadFile(logLevelsCacheFile); err == nil &&
		bytes.Equal(current, data) {
		return
	}
	if err := fileutils.WriteRename(logLevelsCacheFile, data); err != nil {
		log.Errorf("saveLogLevelsCache: %v", err)
	}
}

// loadLogLevelsCache returns the log levels from the cache file, or nil if
// the file does not exist. A file that cannot be parsed or has an
// unexpected schema version - e.g. written by an incompatible EVE version -
// is removed, so newlogd falls back to the compiled-in defaults, the same
// as on a freshly installed device.
func loadLogLevelsCache() *cachedLogLevels {
	data, err := os.ReadFile(logLevelsCacheFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Errorf("loadLogLevelsCache: %v", err)
		}
		return nil
	}
	var levels cachedLogLevels
	if err := json.Unmarshal(data, &levels); err != nil {
		log.Errorf("loadLogLevelsCache: discarding unparsable cache: %v", err)
		removeLogLevelsCache()
		return nil
	}
	if levels.SchemaVersion != logLevelsCacheSchema {
		log.Warnf("loadLogLevelsCache: discarding cache with schema version %d",
			levels.SchemaVersion)
		removeLogLevelsCache()
		return nil
	}
	return &levels
}

func removeLogLevelsCache() {
	if err := os.Remove(logLevelsCacheFile); err != nil && !os.IsNotExist(err) {
		log.Errorf("removeLogLevelsCache: %v", err)
	}
}
