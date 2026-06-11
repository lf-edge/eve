// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

func TestLogLevelsCacheRoundTrip(t *testing.T) {
	g := gomega.NewWithT(t)
	origCacheFile := logLevelsCacheFile
	defer func() { logLevelsCacheFile = origCacheFile }()
	logLevelsCacheFile = filepath.Join(t.TempDir(), logLevelsCacheFilename)

	gcp := types.DefaultConfigItemValueMap()
	gcp.SetGlobalValueString(types.DefaultRemoteLogLevel, "none")
	gcp.SetGlobalValueString(types.SyslogRemoteLogLevel, "none")
	gcp.SetGlobalValueString(types.KernelRemoteLogLevel, "none")
	gcp.SetAgentSettingStringValue("debug", types.RemoteLogLevel, "error")

	levels := logLevelsFromGlobalConfig(gcp)
	saveLogLevelsCache(levels)
	loaded := loadLogLevelsCache()
	g.Expect(loaded).NotTo(gomega.BeNil())
	g.Expect(loaded).To(gomega.Equal(levels))
	g.Expect(loaded.DefaultRemoteLogLevel).To(gomega.Equal("none"))
	g.Expect(loaded.SyslogRemoteLogLevel).To(gomega.Equal("none"))
	g.Expect(loaded.KernelRemoteLogLevel).To(gomega.Equal("none"))
	g.Expect(loaded.AgentRemoteLogLevels).To(gomega.HaveKeyWithValue("debug", "error"))
}

func TestLogLevelsCacheInvalid(t *testing.T) {
	g := gomega.NewWithT(t)
	origCacheFile := logLevelsCacheFile
	defer func() { logLevelsCacheFile = origCacheFile }()
	logLevelsCacheFile = filepath.Join(t.TempDir(), logLevelsCacheFilename)

	// Missing file: no log levels, not an error.
	g.Expect(loadLogLevelsCache()).To(gomega.BeNil())

	// An unparsable file is discarded and removed.
	g.Expect(os.WriteFile(logLevelsCacheFile, []byte("not json"), 0644)).To(gomega.Succeed())
	g.Expect(loadLogLevelsCache()).To(gomega.BeNil())
	_, err := os.Stat(logLevelsCacheFile)
	g.Expect(os.IsNotExist(err)).To(gomega.BeTrue())

	// A cache with an unknown schema version is discarded and removed.
	g.Expect(os.WriteFile(logLevelsCacheFile,
		[]byte(`{"schemaVersion":999}`), 0644)).To(gomega.Succeed())
	g.Expect(loadLogLevelsCache()).To(gomega.BeNil())
	_, err = os.Stat(logLevelsCacheFile)
	g.Expect(os.IsNotExist(err)).To(gomega.BeTrue())
}

func TestApplyLogLevelsRemote(t *testing.T) {
	g := gomega.NewWithT(t)

	gcp := types.DefaultConfigItemValueMap()
	gcp.SetGlobalValueString(types.DefaultRemoteLogLevel, "none")
	gcp.SetGlobalValueString(types.SyslogRemoteLogLevel, "none")
	gcp.SetGlobalValueString(types.KernelRemoteLogLevel, "none")
	gcp.SetAgentSettingStringValue("debug", types.RemoteLogLevel, "error")

	applyLogLevels(logLevelsFromGlobalConfig(gcp))

	g.Expect(agentDefaultRemoteLogLevel.Load()).To(gomega.Equal(logrus.PanicLevel))
	g.Expect(atomic.LoadUint32(&syslogRemotePrio)).To(
		gomega.Equal(types.SyslogKernelLogLevelNum["none"]))
	g.Expect(atomic.LoadUint32(&kernelRemotePrio)).To(
		gomega.Equal(types.SyslogKernelLogLevelNum["none"]))
	level, ok := agentsRemoteLogLevel.Load("debug")
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(level).To(gomega.Equal(logrus.ErrorLevel))
}
