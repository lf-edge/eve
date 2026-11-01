// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package witness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"sigs.k8s.io/yaml"
)

func testStatus() *k3s.ClusterStatus {
	return &k3s.ClusterStatus{
		JoinServerIP:   "10.244.244.2",
		EncryptedToken: "K10secret::server:token",
		WitnessIP:      "10.244.244.5",
		ClusterID:      "7c9e6679-7425-40de-944b-e07fc1f90ae7",
	}
}

// TestEtcdArgsMatchKube is the reason the witness renders its etcd
// settings from Go rather than from an image-supplied config.yaml.
// k3s treats etcd configuration as cluster-critical, and a witness is a
// full voting member storing the same data as every other member, so
// the two must agree. A quota-backend-bytes that drifted below
// pkg/kube's would make the witness raise a NOSPACE alarm first and
// turn the cluster read-only. This holds them together at test time.
func TestEtcdArgsMatchKube(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config.yaml"))
	if err != nil {
		t.Fatalf("read pkg/kube/config.yaml: %v", err)
	}
	var kubeCfg struct {
		EtcdArg []string `json:"etcd-arg"`
	}
	if err := yaml.Unmarshal(raw, &kubeCfg); err != nil {
		t.Fatalf("parse pkg/kube/config.yaml: %v", err)
	}
	if len(kubeCfg.EtcdArg) == 0 {
		t.Fatal("pkg/kube/config.yaml declares no etcd-arg; test is not reading what it thinks")
	}

	witnessArgs := map[string]string{}
	for _, a := range EtcdArgs {
		k, v, _ := strings.Cut(a, "=")
		witnessArgs[k] = v
	}
	for _, a := range kubeCfg.EtcdArg {
		k, v, _ := strings.Cut(a, "=")
		got, ok := witnessArgs[k]
		if !ok {
			t.Errorf("pkg/kube sets etcd %s=%s, witness does not set it at all", k, v)
			continue
		}
		if got != v {
			t.Errorf("etcd %s: witness has %q, pkg/kube has %q", k, got, v)
		}
	}
}

// TestConfigureWritesEveryDropIn checks the rendered set and the values
// that come from the controller.
func TestConfigureWritesEveryDropIn(t *testing.T) {
	dir := t.TempDir()
	orig := k3s.K3sConfigDir
	k3s.K3sConfigDir = dir
	t.Cleanup(func() { k3s.K3sConfigDir = orig })

	if err := Configure(testStatus()); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	merged := map[string]any{}
	for _, name := range []string{
		nodeNameConfig, clusterConfig, networkConfig, etcdOnlyConfig, etcdArgsConfig,
	} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		one := map[string]any{}
		if err := yaml.Unmarshal(raw, &one); err != nil {
			t.Fatalf("parse %s: %v (content: %s)", name, err, raw)
		}
		for k, v := range one {
			merged[k] = v
		}
	}

	want := map[string]any{
		"node-name":                  NodeName,
		"server":                     "https://10.244.244.2:6443",
		"token":                      "K10secret::server:token",
		"node-ip":                    "10.244.244.5",
		"disable-agent":              true,
		"disable-apiserver":          true,
		"disable-scheduler":          true,
		"disable-controller-manager": true,
	}
	for k, v := range want {
		if merged[k] != v {
			t.Errorf("%s = %v, want %v", k, merged[k], v)
		}
	}
}

// TestConfigureRejectsIncompleteStatus: each missing field would
// otherwise surface as an obscure k3s failure minutes later.
func TestConfigureRejectsIncompleteStatus(t *testing.T) {
	dir := t.TempDir()
	orig := k3s.K3sConfigDir
	k3s.K3sConfigDir = dir
	t.Cleanup(func() { k3s.K3sConfigDir = orig })

	cases := map[string]func(*k3s.ClusterStatus){
		"no witness IP": func(cs *k3s.ClusterStatus) { cs.WitnessIP = "" },
		"no join server": func(cs *k3s.ClusterStatus) {
			cs.JoinServerIP = ""
		},
		"no token": func(cs *k3s.ClusterStatus) { cs.EncryptedToken = "" },
	}
	for name, mangle := range cases {
		t.Run(name, func(t *testing.T) {
			cs := testStatus()
			mangle(cs)
			if err := Configure(cs); err == nil {
				t.Error("Configure accepted an incomplete cluster status")
			}
		})
	}
	if err := Configure(nil); err == nil {
		t.Error("Configure accepted a nil cluster status")
	}
}

// TestBracketIPv6 covers the URL form for a literal v6 seed address.
func TestBracketIPv6(t *testing.T) {
	cases := map[string]string{
		"10.244.244.2": "10.244.244.2",
		"fd00::2":      "[fd00::2]",
		"":             "",
	}
	for in, want := range cases {
		if got := bracketIPv6(in); got != want {
			t.Errorf("bracketIPv6(%q) = %q, want %q", in, got, want)
		}
	}
}
