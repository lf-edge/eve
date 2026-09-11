// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"os"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

const storageWarning = "WARNING: cluster storage not ready"

// printSummary renders one diag summary for the given volumemgr status and
// returns what landed in the state file. Leaving gotDNS, gotBC and gotDPCList
// unset stops printOutput right after the storage and application lines, which
// is as far as these tests need it to go and keeps them free of any pubsub
// subscription.
func printSummary(t *testing.T, status types.VolumeMgrStatus) string {
	t.Helper()
	log = base.NewSourceLogObject(logrus.StandardLogger(), "diag", 0)

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	stateFile, err := os.CreateTemp(t.TempDir(), "diag.out")
	if err != nil {
		t.Fatal(err)
	}
	defer stateFile.Close()

	ctx := &diagContext{
		DeviceNetworkStatus:  &types.DeviceNetworkStatus{},
		DevicePortConfigList: &types.DevicePortConfigList{},
		volumeMgrStatus:      status,
	}
	ctx.ph = PrintIfSpaceInit(devNull, stateFile.Name(), 100, 200)
	printOutput(ctx, "test")

	content, err := os.ReadFile(stateFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func TestDiagReportsUnmetStorageCondition(t *testing.T) {
	const condition = "longhorn not ready: daemonset:longhorn-manager not running on node"
	out := printSummary(t, types.VolumeMgrStatus{
		Name:           "volumemgr",
		UnmetCondition: condition,
	})
	if !strings.Contains(out, storageWarning+": "+condition) {
		t.Fatalf("summary must name the outstanding storage gate, got:\n%s", out)
	}
}

func TestDiagQuietWhenStorageIsReady(t *testing.T) {
	out := printSummary(t, types.VolumeMgrStatus{
		Name:        "volumemgr",
		Initialized: true,
	})
	if strings.Contains(out, storageWarning) {
		t.Fatalf("a node with usable storage must not be warned about, got:\n%s", out)
	}
}

// An absent status must not be reported as a storage failure.
func TestDiagQuietBeforeVolumeMgrPublishes(t *testing.T) {
	out := printSummary(t, types.VolumeMgrStatus{})
	if strings.Contains(out, storageWarning) {
		t.Fatalf("no warning is due before volumemgr publishes, got:\n%s", out)
	}
}
