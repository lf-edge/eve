// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/onsi/gomega"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// ---- loadGlobalConfigImpl tests ----

const testSSHKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey test@example.com"

func TestLoadGlobalConfigBothMissing(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	ctx := initGetConfigCtx(g)

	dir := t.TempDir()
	result := loadGlobalConfigImpl(ctx,
		filepath.Join(dir, "global.json"),
		filepath.Join(dir, "authorized_keys"))
	g.Expect(result).To(gomega.BeFalse())
}

func TestLoadGlobalConfigSuccess(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	ctx := initGetConfigCtx(g)

	dir := t.TempDir()

	// Write a GlobalConfig JSON that sets a recognisable value.
	cfg := types.DefaultConfigItemValueMap()
	cfg.SetGlobalValueInt(types.ConfigInterval, 42)
	data, err := json.Marshal(cfg)
	g.Expect(err).To(gomega.BeNil())

	globalFile := filepath.Join(dir, "global.json")
	g.Expect(os.WriteFile(globalFile, data, 0644)).To(gomega.Succeed())

	result := loadGlobalConfigImpl(ctx, globalFile, filepath.Join(dir, "no_keys"))
	g.Expect(result).To(gomega.BeTrue())
	g.Expect(ctx.zedagentCtx.globalConfig.GlobalValueInt(types.ConfigInterval)).
		To(gomega.Equal(uint32(42)))
}

// TestLoadGlobalConfigPrefersGlobalOverAuthKeys: when GlobalConfig
// exists, its (possibly empty) debug.enable.ssh wins over the
// authorized_keys file. Uses a non-default ConfigInterval value as a
// fingerprint so the test would fail if the bootstrap branch were
// silently taken instead.
func TestLoadGlobalConfigPrefersGlobalOverAuthKeys(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	ctx := initGetConfigCtx(g)

	dir := t.TempDir()

	// GlobalConfig with EMPTY debug.enable.ssh AND a non-default
	// ConfigInterval — the latter is the fingerprint that the
	// GlobalConfig branch ran (bootstrap branch would leave it
	// at the default).
	cfg := types.DefaultConfigItemValueMap()
	cfg.SetGlobalValueString(types.SSHAuthorizedKeys, "")
	cfg.SetGlobalValueInt(types.ConfigInterval, 17)
	data, err := json.Marshal(cfg)
	g.Expect(err).To(gomega.BeNil())

	globalFile := filepath.Join(dir, "global.json")
	authKeysFile := filepath.Join(dir, "authorized_keys")
	g.Expect(os.WriteFile(globalFile, data, 0644)).To(gomega.Succeed())
	g.Expect(os.WriteFile(authKeysFile, []byte(testSSHKey+"\n"), 0644)).To(gomega.Succeed())

	result := loadGlobalConfigImpl(ctx, globalFile, authKeysFile)
	g.Expect(result).To(gomega.BeTrue())
	g.Expect(ctx.zedagentCtx.globalConfig.GlobalValueString(types.SSHAuthorizedKeys)).
		To(gomega.Equal(""))
	g.Expect(ctx.zedagentCtx.globalConfig.GlobalValueInt(types.ConfigInterval)).
		To(gomega.Equal(uint32(17)))
}

// TestLoadGlobalConfigBootstrapFromAuthorizedKeys: no GlobalConfig
// on /config, only authorized_keys. Synthesizes a default
// ConfigItemValueMap with debug.enable.ssh set to the file content.
func TestLoadGlobalConfigBootstrapFromAuthorizedKeys(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	ctx := initGetConfigCtx(g)

	dir := t.TempDir()
	globalFile := filepath.Join(dir, "global.json") // intentionally absent
	authKeysFile := filepath.Join(dir, "authorized_keys")
	g.Expect(os.WriteFile(authKeysFile, []byte(testSSHKey+"\n"), 0644)).To(gomega.Succeed())

	result := loadGlobalConfigImpl(ctx, globalFile, authKeysFile)
	g.Expect(result).To(gomega.BeTrue())
	g.Expect(ctx.zedagentCtx.globalConfig.GlobalValueString(types.SSHAuthorizedKeys)).
		To(gomega.Equal(testSSHKey))
}

// TestLoadGlobalConfigBootstrapEmptyAuthKeys: empty authorized_keys
// with no GlobalConfig must not publish a default ConfigItemValueMap.
func TestLoadGlobalConfigBootstrapEmptyAuthKeys(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	ctx := initGetConfigCtx(g)

	dir := t.TempDir()
	globalFile := filepath.Join(dir, "global.json") // intentionally absent
	authKeysFile := filepath.Join(dir, "authorized_keys")
	g.Expect(os.WriteFile(authKeysFile, []byte(""), 0644)).To(gomega.Succeed())

	result := loadGlobalConfigImpl(ctx, globalFile, authKeysFile)
	g.Expect(result).To(gomega.BeFalse())
}

func TestLoadGlobalConfigMalformedJSON(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	ctx := initGetConfigCtx(g)

	dir := t.TempDir()
	globalFile := filepath.Join(dir, "global.json")
	g.Expect(os.WriteFile(globalFile, []byte("{not valid json}"), 0644)).To(gomega.Succeed())

	result := loadGlobalConfigImpl(ctx, globalFile, filepath.Join(dir, "no_keys"))
	g.Expect(result).To(gomega.BeFalse())
}
