// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"strings"
	"time"

	"github.com/lf-edge/eve/evetest"
)

// lruGenOffParamKey selects whether the multi-gen LRU is held off on the
// device, to tell an MGLRU reclaim effect apart from the rest of a kernel
// change. Only the amd64 hwe kernel builds it.
const lruGenOffParamKey = "LRU_GEN_OFF"

// lruGenPoll is how often the switch is re-checked. The kernel has no boot
// parameter for it, so every boot comes up with the build default and the
// switch has to be cleared again before the CDI upload starts, which follows
// k3s, CDI and Longhorn coming up by minutes.
const lruGenPoll = 10 * time.Second

func lruGenOffParameterDefinition() evetest.TestParameterDefinition {
	return evetest.TestParameterDefinition{
		Key:          lruGenOffParamKey,
		DefaultValue: false,
		Description: evetest.TestParameterDescription{
			Summary: "Hold /sys/kernel/mm/lru_gen/enabled at 0 on every boot",
			Default: "false",
		},
	}
}

// lruGenOffScript clears the switch where the kernel has one and reports what
// it found: "absent", "off", or "cleared <previous value>".
const lruGenOffScript = `f=/sys/kernel/mm/lru_gen/enabled
[ -e $f ] || { echo absent; exit 0; }
v=$(cat $f)
[ "$v" = 0x0000 ] && { echo off; exit 0; }
echo n > $f && echo "cleared $v -> $(cat $f)"`

// holdLRUGenOff keeps the multi-gen LRU disabled on the device for the rest of
// the process, logging each state change and every time it had to clear it.
func holdLRUGenOff(device *evetest.EdgeDevice) {
	evetest.Logger().Infof("LRU_GEN_OFF: holding /sys/kernel/mm/lru_gen/enabled at 0")
	last := ""
	for {
		out, err := runEVE(device, lruGenOffScript)
		state := strings.TrimSpace(out)
		switch {
		case err != nil:
			state = "unreachable"
		case strings.HasPrefix(state, "cleared"):
			evetest.Logger().Infof("LRU_GEN_OFF: %s", state)
			state = "off"
		}
		if state != last {
			evetest.Logger().Infof("LRU_GEN_OFF: switch %s", state)
			last = state
		}
		time.Sleep(lruGenPoll)
	}
}
