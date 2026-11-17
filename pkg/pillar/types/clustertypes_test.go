// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// ENClusterAppStatus.Equal

func TestENClusterAppStatusEqual(t *testing.T) {
	s1 := ENClusterAppStatus{
		ScheduledOnThisNode: true,
		AppIsVMI:            true,
		VMIName:             "myapp",
		VNCPort:             5901,
	}
	s2 := s1
	assert.True(t, s1.Equal(s2))

	s2.ScheduledOnThisNode = false
	assert.False(t, s1.Equal(s2))

	s2 = s1
	s2.VMIName = "otherapp"
	assert.False(t, s1.Equal(s2))

	s2 = s1
	s2.VNCPort = 5902
	assert.False(t, s1.Equal(s2))
}

// EdgeNodeClusterConfig.Key

func TestEdgeNodeClusterConfigKey(t *testing.T) {
	cfg := EdgeNodeClusterConfig{}
	assert.Equal(t, cfg.ClusterID.UUID.String(), cfg.Key())
}

// EdgeNodeClusterConfig.NativeK8sOrchestrationEnabled

func TestNativeK8sOrchestrationEnabled(t *testing.T) {
	cases := []struct {
		name        string
		clusterType ClusterType
		flag        bool
		want        bool
	}{
		{"k3s-base is always native", ClusterTypeK3sBase, false, true},
		{"k3s-base with flag is native", ClusterTypeK3sBase, true, true},
		{"replicated storage without flag", ClusterTypeReplicatedStorage, false, false},
		{"replicated storage with flag", ClusterTypeReplicatedStorage, true, true},
		{"none without flag", ClusterTypeNone, false, false},
		{"none with flag is not native", ClusterTypeNone, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := EdgeNodeClusterConfig{
				ClusterType:                  tc.clusterType,
				EnableNativeK8SOrchestration: tc.flag,
			}
			assert.Equal(t, tc.want, cfg.NativeK8sOrchestrationEnabled())
		})
	}
}

// EdgeNodeClusterConfig.IsTieBreakerNode

func TestIsTieBreakerNode(t *testing.T) {
	const (
		tieBreaker = "5a0283de-d69a-4d4a-877f-63f9fcfcb929"
		otherNode  = "e3342f18-c354-49e7-9a00-f3ff3a2f3db0"
	)
	tbUUID, err := uuid.FromString(tieBreaker)
	assert.NoError(t, err)

	cases := []struct {
		name       string
		configured uuid.UUID
		nodeUUID   string
		want       bool
	}{
		{"designated tie-breaker matches", tbUUID, tieBreaker, true},
		{"tie-breaker matches upper case", tbUUID, strings.ToUpper(tieBreaker), true},
		{"storage node does not match", tbUUID, otherNode, false},
		// No tie-breaker designated: no node may be treated as one, otherwise a
		// node with an empty UUID would match the zero value.
		{"no tie-breaker designated", uuid.Nil, otherNode, false},
		{"no tie-breaker designated, empty node uuid", uuid.Nil, "", false},
		{"unparsable node uuid", tbUUID, "not-a-uuid", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := EdgeNodeClusterConfig{
				TieBreakerNodeID: UUIDandVersion{UUID: tc.configured},
			}
			assert.Equal(t, tc.want, cfg.IsTieBreakerNode(tc.nodeUUID))
		})
	}
}

func TestVmiVNCConfig_JSONRoundTrip(t *testing.T) {
	cases := []struct {
		name        string
		in          VmiVNCConfig
		mustContain string // substring that must appear
		mustExclude string // substring that must NOT appear
	}{
		{
			name:        "edgeview writer includes CallerPID and AppUUID",
			in:          VmiVNCConfig{VMIName: "vmi", VNCPort: 5910, AppUUID: "app-uuid", CallerPID: 1234},
			mustContain: `"CallerPID":1234`,
		},
		{
			name:        "remote-console writer omits CallerPID",
			in:          VmiVNCConfig{VMIName: "vmi", VNCPort: 5910, AppUUID: "app-uuid"},
			mustExclude: "CallerPID",
		},
		{
			name:        "legacy writer omits AppUUID",
			in:          VmiVNCConfig{VMIName: "vmi", VNCPort: 5910, CallerPID: 1234},
			mustExclude: "AppUUID",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			s := string(buf)
			if tc.mustContain != "" && !strings.Contains(s, tc.mustContain) {
				t.Errorf("missing %q in %s", tc.mustContain, s)
			}
			if tc.mustExclude != "" && strings.Contains(s, tc.mustExclude) {
				t.Errorf("unexpected %q in %s", tc.mustExclude, s)
			}

			var back VmiVNCConfig
			if err := json.Unmarshal(buf, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if back != tc.in {
				t.Errorf("round-trip mismatch: got %+v want %+v", back, tc.in)
			}
		})
	}
}

// withProcPath swaps procPath to a tmpdir for the duration of one test.
func withProcPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := procPath
	procPath = dir
	t.Cleanup(func() { procPath = orig })
	return dir
}

// writeComm writes a fake /proc/<pid>/comm file.
func writeComm(t *testing.T, root string, pid int, comm string) {
	t.Helper()
	procDir := filepath.Join(root, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "comm"), []byte(comm+"\n"), 0644); err != nil {
		t.Fatalf("write comm: %v", err)
	}
}

func TestOwnerAlive(t *testing.T) {
	cases := []struct {
		name string
		cfg  VmiVNCConfig
		comm string // "" means no comm file at that PID (dead/absent)
		want bool
	}{
		{
			name: "CallerPID unset",
			cfg:  VmiVNCConfig{CallerPID: 0},
			want: false,
		},
		{
			name: "negative CallerPID",
			cfg:  VmiVNCConfig{CallerPID: -1},
			want: false,
		},
		{
			name: "PID dead (no /proc entry)",
			cfg:  VmiVNCConfig{CallerPID: 99999},
			want: false,
		},
		{
			name: "PID live but reused by another program",
			cfg:  VmiVNCConfig{CallerPID: 12345},
			comm: "bash",
			want: false,
		},
		{
			name: "PID live and still edge-view",
			cfg:  VmiVNCConfig{CallerPID: 12345},
			comm: "edge-view",
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := withProcPath(t)
			if tc.comm != "" {
				writeComm(t, root, tc.cfg.CallerPID, tc.comm)
			}
			if got := tc.cfg.OwnerAlive(); got != tc.want {
				t.Errorf("OwnerAlive() = %v, want %v", got, tc.want)
			}
		})
	}
}

func testENCC() EdgeNodeClusterConfig {
	_, prefix, _ := net.ParseCIDR("192.0.2.1/28")
	return EdgeNodeClusterConfig{
		Initialized:      true,
		Valid:            true,
		ClusterName:      "cluster1",
		ClusterID:        UUIDandVersion{UUID: uuid.FromStringOrNil("11111111-2222-3333-4444-555555555555")},
		ClusterInterface: "eth0",
		ClusterIPPrefix:  prefix,
		JoinServerIP:     net.ParseIP("192.0.2.1"),
		BootstrapNode:    true,
		ClusterType:      ClusterTypeK3sBase,
		CipherToken: CipherBlockStatus{
			CipherBlockID: "block1",
			IsCipher:      true,
			CipherData:    []byte("secret-token-ciphertext"),
		},
	}
}

func TestEdgeNodeClusterConfigChangedFields(t *testing.T) {
	old := testENCC()

	// No change, including nil vs empty slices
	same := testENCC()
	same.MasterNodeIDs = []uuid.UUID{}
	assert.Empty(t, same.changedFields(old))

	// Type flip plus the native orchestration flag
	cfg := testENCC()
	cfg.ClusterType = ClusterTypeReplicatedStorage
	cfg.EnableNativeK8SOrchestration = true
	assert.Equal(t, []string{
		"ClusterType: K3sBase(1) -> ReplicatedStorage(2)",
		"EnableNativeK8SOrchestration: false -> true",
	}, cfg.changedFields(old))

	// Network and membership fields
	cfg = testENCC()
	_, cfg.ClusterIPPrefix, _ = net.ParseCIDR("198.51.100.0/28")
	cfg.JoinServerIP = net.ParseIP("198.51.100.1")
	cfg.MasterNodeIDs = []uuid.UUID{uuid.FromStringOrNil("aaaaaaaa-2222-3333-4444-555555555555")}
	cfg.LBInterfaces = []LBInterfaceConfig{{Interface: "eth1", IPPrefix: "192.168.1.24/29"}}
	assert.Equal(t, []string{
		"ClusterIPPrefix: 192.0.2.0/28 -> 198.51.100.0/28",
		"JoinServerIP: 192.0.2.1 -> 198.51.100.1",
		"LBInterfaces: [] -> [{eth1 192.168.1.24/29}]",
		"MasterNodeIDs: [] -> [aaaaaaaa-2222-3333-4444-555555555555]",
	}, cfg.changedFields(old))

	// Cipher block changes are named and counted but the content is not printed
	cfg = testENCC()
	cfg.CipherToken.CipherData = []byte("other-token-ciphertext")
	cfg.CipherGzipRegistrationManifestYaml = cfg.CipherToken
	changes := cfg.changedFields(old)
	// Both fields carry the same block, so it is one change
	assert.Equal(t, []string{
		"CipherToken+CipherGzipRegistrationManifestYaml: changed",
	}, changes)

	// Different blocks are separate changes
	cfg.CipherGzipRegistrationManifestYaml.CipherData = []byte("manifest-ciphertext")
	changes = cfg.changedFields(old)
	assert.Equal(t, []string{
		"CipherToken: changed",
		"CipherGzipRegistrationManifestYaml: changed",
	}, changes)
	for _, c := range changes {
		assert.NotContains(t, c, "ciphertext")
	}

	// A locally resolved cipher context or error is not a controller change
	cfg = testENCC()
	cfg.CipherToken.CipherContext = &CipherContext{ContextID: "ctx"}
	cfg.CipherToken.SetErrorNow("decrypt failed")
	assert.Empty(t, cfg.changedFields(old))

	// Every field is covered, so a change to any of them is named
	cfg = testENCC()
	cfg.QuorumRecoveryGeneration = 3
	cfg.WitnessIP = net.ParseIP("192.0.2.5")
	cfg.TieBreakerNodeID = UUIDandVersion{UUID: uuid.FromStringOrNil("bbbbbbbb-2222-3333-4444-555555555555")}
	assert.Equal(t, []string{
		"TieBreakerNodeID: 00000000-0000-0000-0000-000000000000 -> bbbbbbbb-2222-3333-4444-555555555555",
		"WitnessIP: <nil> -> 192.0.2.5",
		"QuorumRecoveryGeneration: 0 -> 3",
	}, cfg.changedFields(old))

	// Same prefix behind a different pointer is not a change
	cfg = testENCC()
	_, cfg.ClusterIPPrefix, _ = net.ParseCIDR("192.0.2.1/28")
	cfg.JoinServerIP = net.ParseIP("192.0.2.1").To4()
	assert.Empty(t, cfg.changedFields(old))

	// Nil prefix must not panic
	cfg = testENCC()
	cfg.ClusterIPPrefix = nil
	assert.Equal(t, []string{"ClusterIPPrefix: 192.0.2.0/28 -> <nil>"}, cfg.changedFields(old))
}

func TestEdgeNodeClusterConfigLog(t *testing.T) {
	logBuf := &strings.Builder{}
	logger := logrus.New()
	logger.SetOutput(logBuf)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck

	old := testENCC()
	cfg := testENCC()
	cfg.ClusterType = ClusterTypeReplicatedStorage
	cfg.CipherToken.CipherData = []byte("other-token-ciphertext")

	EdgeNodeClusterConfig{Initialized: true}.LogCreate(log)
	old.LogCreate(log)
	cfg.LogModify(log, old)
	cfg.LogModify(log, "not a cluster config") // logs an error, must not exit
	cfg.LogDelete(log)

	out := logBuf.String()
	assert.Contains(t, out, "EdgeNodeClusterConfig create: no cluster")
	assert.Contains(t, out, "EdgeNodeClusterConfig create: Initialized: true, Valid: true, "+
		"ClusterName: cluster1, ClusterID: 11111111-2222-3333-4444-555555555555, "+
		"ClusterInterface: eth0, ClusterIPPrefix: 192.0.2.0/28, IsWorkerNode: false, "+
		"JoinServerIP: 192.0.2.1, BootstrapNode: true, ClusterType: K3sBase(1), ")
	assert.Contains(t, out, "QuorumRecoveryGeneration: 0")
	assert.Contains(t, out, "EdgeNodeClusterConfig modify: old object is string")
	assert.Contains(t, out, "EdgeNodeClusterConfig modify: 2 field(s) changed: "+
		"ClusterType: K3sBase(1) -> ReplicatedStorage(2), CipherToken: changed")
	assert.Contains(t, out, "EdgeNodeClusterConfig delete")
	assert.NotContains(t, out, "ciphertext")
}

// A new field is logged by LogCreate and LogModify. Before adding it here,
// check that it holds no secret; cipher blocks need adding to cipherChanges.
func TestEdgeNodeClusterConfigLoggedFields(t *testing.T) {
	var names []string
	typ := reflect.TypeOf(EdgeNodeClusterConfig{})
	for i := 0; i < typ.NumField(); i++ {
		names = append(names, typ.Field(i).Name)
	}
	assert.Equal(t, []string{
		"Initialized", "Valid", "ClusterName", "ClusterID", "ClusterInterface",
		"ClusterIPPrefix", "IsWorkerNode", "JoinServerIP", "BootstrapNode",
		"CipherToken", "CipherGzipRegistrationManifestYaml", "ClusterType",
		"TieBreakerNodeID", "EnableNativeK8SOrchestration", "LBInterfaces",
		"MasterNodeIDs", "WitnessIP", "WitnessConfigError",
		"QuorumRecoveryGeneration",
	}, names)
}
