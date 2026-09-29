// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/encconfig"
)

// Relative to this package: the base config the kube image installs as
// /etc/rancher/k3s/config.yaml, and the manifests it copies to /etc/kube.
const (
	baseK3sConfigPath = "../../config.yaml"
	cfgManifestsDir   = "../../cfg-manifests"
)

// TestEffectiveDisableKeepsServicelbAndTraefik renders the drop-ins
// kube-init writes beside the base config and applies k3s's merge rule for
// config.yaml.d: files load in lexical order, a bare key replaces what
// earlier files set, and "key+" appends to it. servicelb and traefik must
// stay disabled whatever else a drop-in disables, or servicelb's hostPort
// DNAT exposes Traefik on 80/443 of every node address. The user-override
// drop-in is left out, since disabling differently is its purpose.
func TestEffectiveDisableKeepsServicelbAndTraefik(t *testing.T) {
	base, err := os.ReadFile(baseK3sConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	cs := &ClusterStatus{
		ClusterInterface: "eth0",
		JoinServerIP:     "10.0.0.1",
		EncryptedToken:   "tok",
		ClusterIP:        "10.0.0.2",
		ClusterIPIsReady: true,
		ClusterID:        "u",
	}
	variants := []struct {
		name            string
		etcdInitialized bool
		write           func(path string) error
	}{
		{"bootstrap first boot", false, func(path string) error {
			return writeBootstrapConfig(path, cs, true)
		}},
		{"bootstrap restart", true, func(path string) error {
			return writeBootstrapConfig(path, cs, false)
		}},
		{"join", true, func(path string) error {
			return writeJoinConfig(context.Background(), path, cs, false)
		}},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			configDir, _ := shadowPaths(t)
			shadowEtcdInitialized(t, v.etcdInitialized)
			encconfig.ResetForTest()
			t.Cleanup(encconfig.ResetForTest)

			if err := WriteNodeName("node"); err != nil {
				t.Fatal(err)
			}
			if err := v.write(filepath.Join(configDir, ClusterConfig)); err != nil {
				t.Fatal(err)
			}
			if err := provisionDisableLocalPath(); err != nil {
				t.Fatal(err)
			}
			copyShippedDropIns(t, configDir)

			disabled := disableList(t, string(base), nil)
			entries, err := os.ReadDir(configDir)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			sort.Strings(names)
			for _, name := range names {
				disabled = disableList(t,
					readFile(t, filepath.Join(configDir, name)), disabled)
			}
			for _, want := range []string{"servicelb", "traefik", "local-storage"} {
				if !slices.Contains(disabled, want) {
					t.Errorf("effective disable list %v lacks %q", disabled, want)
				}
			}
		})
	}
}

// copyShippedDropIns copies the numbered drop-ins the kube image ships under
// /etc/kube, such as MultiNodeWatchCache, into configDir. One named like a
// drop-in kube-init renders is an error: kube-init never reads it, so it can
// only mislead.
func copyShippedDropIns(t *testing.T, configDir string) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(cfgManifestsDir, "[0-9][0-9]-*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		dst := filepath.Join(configDir, filepath.Base(p))
		if _, err := os.Stat(dst); err == nil {
			t.Errorf("%s has the name of a drop-in kube-init renders", p)
			continue
		}
		if err := os.WriteFile(dst, []byte(readFile(t, p)), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

// disableList applies body's top-level "disable" or "disable+" key, if
// any, to the list prior, and returns the result.
func disableList(t *testing.T, body string, prior []string) []string {
	t.Helper()
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		key, value, ok := strings.Cut(line, ":")
		if !ok || (key != "disable" && key != "disable+") {
			continue
		}
		value, _, _ = strings.Cut(value, "#")
		value = strings.Trim(strings.TrimSpace(value), "[]")
		var values []string
		for _, v := range strings.Split(value, ",") {
			if v = strings.Trim(strings.TrimSpace(v), `"'`); v != "" {
				values = append(values, v)
			}
		}
		for _, next := range lines[i+1:] {
			item, isItem := strings.CutPrefix(strings.TrimSpace(next), "- ")
			if !isItem || !strings.HasPrefix(next, " ") {
				break
			}
			values = append(values, strings.Trim(strings.TrimSpace(item), `"'`))
		}
		if key == "disable+" {
			return append(slices.Clone(prior), values...)
		}
		return values
	}
	return prior
}
