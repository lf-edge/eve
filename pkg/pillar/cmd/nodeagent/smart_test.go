// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func TestParseSMARTDataFiles_BothPresent(t *testing.T) {
	initTestLog()
	dir := t.TempDir()
	currPath := filepath.Join(dir, "curr.json")
	prevPath := filepath.Join(dir, "prev.json")
	mustWrite(t, currPath,
		`{"power_on_time":{"hours":100},"power_cycle_count":7}`)
	mustWrite(t, prevPath,
		`{"power_on_time":{"hours":50},"power_cycle_count":5}`)

	curr := types.NewSmartDataWithDefaults()
	prev := types.NewSmartDataWithDefaults()
	parseSMARTDataFiles(currPath, prevPath, curr, prev)

	if curr.PowerCycleCount != 7 || curr.PowerOnTime.Hours != 100 {
		t.Errorf("curr not populated: %+v", curr)
	}
	if prev.PowerCycleCount != 5 || prev.PowerOnTime.Hours != 50 {
		t.Errorf("prev not populated: %+v", prev)
	}
}

func TestParseSMARTDataFiles_PrevMissing(t *testing.T) {
	initTestLog()
	dir := t.TempDir()
	currPath := filepath.Join(dir, "curr.json")
	prevPath := filepath.Join(dir, "no-such-file.json")
	mustWrite(t, currPath,
		`{"power_on_time":{"hours":10},"power_cycle_count":3}`)

	curr := types.NewSmartDataWithDefaults()
	prev := types.NewSmartDataWithDefaults()
	parseSMARTDataFiles(currPath, prevPath, curr, prev)

	if curr.PowerCycleCount != 3 {
		t.Errorf("curr not populated: %+v", curr)
	}
	if prev.PowerCycleCount != -1 {
		t.Errorf("prev should retain default -1, got %d", prev.PowerCycleCount)
	}
}

func TestParseSMARTDataFiles_MalformedJSON(t *testing.T) {
	initTestLog()
	dir := t.TempDir()
	currPath := filepath.Join(dir, "curr.json")
	prevPath := filepath.Join(dir, "prev.json")
	mustWrite(t, currPath, "{not valid json")
	mustWrite(t, prevPath, "")

	curr := types.NewSmartDataWithDefaults()
	prev := types.NewSmartDataWithDefaults()
	parseSMARTDataFiles(currPath, prevPath, curr, prev)

	if curr.PowerCycleCount != -1 || prev.PowerCycleCount != -1 {
		t.Errorf("malformed JSON should leave defaults, got curr=%+v prev=%+v",
			curr, prev)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
