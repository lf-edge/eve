// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// AllSlots

func TestAllSlots(t *testing.T) {
	slots := AllSlots()
	assert.ElementsMatch(t, []SlotName{SlotIMGA, SlotIMGB, SlotIMGC}, slots)
}

// EvalStatus.IsOnboardingAllowed

func TestEvalStatusIsOnboardingAllowed(t *testing.T) {
	// Non-evaluation platform → always true
	s := EvalStatus{IsEvaluationPlatform: false}
	assert.True(t, s.IsOnboardingAllowed())

	// Eval platform, AllowOnboard=false → false
	s = EvalStatus{IsEvaluationPlatform: true, AllowOnboard: false, Phase: EvalPhaseInit}
	assert.False(t, s.IsOnboardingAllowed())

	// Eval platform, AllowOnboard=true, Init phase → true
	s.AllowOnboard = true
	assert.True(t, s.IsOnboardingAllowed())

	// Eval platform, Final phase, AllowOnboard=true → true
	s.Phase = EvalPhaseFinal
	assert.True(t, s.IsOnboardingAllowed())

	// Eval platform, Testing phase, AllowOnboard=true → true (manual override)
	s.Phase = EvalPhaseTesting
	s.AllowOnboard = true
	assert.True(t, s.IsOnboardingAllowed())

	// Eval platform, unknown phase, AllowOnboard=true → false (conservative)
	s.Phase = EvalPhase("unknown")
	assert.False(t, s.IsOnboardingAllowed())
}

// EvalStatus.OnboardingBlockReason

func TestEvalStatusOnboardingBlockReason(t *testing.T) {
	// Non-eval → no block reason
	s := EvalStatus{IsEvaluationPlatform: false}
	assert.Equal(t, "", s.OnboardingBlockReason())

	// Eval, allowed → no block reason
	s = EvalStatus{IsEvaluationPlatform: true, AllowOnboard: true, Phase: EvalPhaseFinal}
	assert.Equal(t, "", s.OnboardingBlockReason())

	// Eval, blocked, init phase
	s = EvalStatus{IsEvaluationPlatform: true, AllowOnboard: false, Phase: EvalPhaseInit}
	assert.Equal(t, "evaluation platform initializing", s.OnboardingBlockReason())

	// Eval, blocked, testing phase
	s.Phase = EvalPhaseTesting
	assert.Equal(t, "evaluation platform testing in progress", s.OnboardingBlockReason())

	// Eval, final phase, explicitly disabled
	s.Phase = EvalPhaseFinal
	assert.Equal(t, "evaluation complete but onboarding explicitly disabled", s.OnboardingBlockReason())

	// Eval, unknown phase
	s.Phase = EvalPhase("weird")
	assert.Equal(t, "evaluation platform not ready", s.OnboardingBlockReason())
}

// EvalStatus.ProgressPercent

func TestEvalStatusProgressPercent(t *testing.T) {
	// No test duration → 0
	s := EvalStatus{}
	assert.Equal(t, 0, s.ProgressPercent())

	// Started 0 seconds ago with 1 minute duration
	s = EvalStatus{
		TestStartTime: time.Now(),
		TestDuration:  time.Minute,
	}
	p := s.ProgressPercent()
	assert.GreaterOrEqual(t, p, 0)
	assert.LessOrEqual(t, p, 10) // just started

	// Elapsed > duration → 100%
	s.TestStartTime = time.Now().Add(-2 * time.Minute)
	assert.Equal(t, 100, s.ProgressPercent())
}

// EvalStatus.RebootStatusString

func TestEvalStatusRebootStatusString(t *testing.T) {
	s := EvalStatus{RebootCountdown: 0}
	assert.Equal(t, "", s.RebootStatusString())

	s.RebootCountdown = 30
	assert.Equal(t, "Requesting reboot in 30 sec", s.RebootStatusString())
}

// EvalStatus.DetailedNote

func TestEvalStatusDetailedNote(t *testing.T) {
	// No extra context → just the note
	s := EvalStatus{Note: "all good"}
	assert.Equal(t, "all good", s.DetailedNote())

	// With reboot countdown
	s.RebootCountdown = 10
	note := s.DetailedNote()
	assert.Contains(t, note, "all good")
	assert.Contains(t, note, "reboot in 10 sec")

	// With TimeStatusString non-empty (Testing phase, in progress)
	s2 := EvalStatus{
		Note:          "testing",
		Phase:         EvalPhaseTesting,
		TestStartTime: time.Now(),
		TestDuration:  time.Minute,
	}
	note2 := s2.DetailedNote()
	assert.Contains(t, note2, "testing")
	assert.Contains(t, note2, "Progress")
}

// EvalStatus.RemainingTime

func TestEvalStatusRemainingTime(t *testing.T) {
	// No start time → 0
	s := EvalStatus{}
	assert.Equal(t, time.Duration(0), s.RemainingTime())

	// No duration → 0
	s = EvalStatus{TestStartTime: time.Now()}
	assert.Equal(t, time.Duration(0), s.RemainingTime())

	// Started just now with 1 minute duration
	s = EvalStatus{
		TestStartTime: time.Now(),
		TestDuration:  time.Minute,
	}
	remaining := s.RemainingTime()
	assert.Greater(t, remaining, time.Duration(0))
	assert.LessOrEqual(t, remaining, time.Minute)

	// Already past deadline → 0
	s.TestStartTime = time.Now().Add(-2 * time.Minute)
	assert.Equal(t, time.Duration(0), s.RemainingTime())
}

// EvalStatus.TimeStatusString

func TestEvalStatusTimeStatusString(t *testing.T) {
	// Not in testing phase → empty string
	s := EvalStatus{Phase: EvalPhaseFinal}
	assert.Equal(t, "", s.TimeStatusString())

	// Testing phase, past deadline → "Test complete" message
	s = EvalStatus{
		Phase:         EvalPhaseTesting,
		TestStartTime: time.Now().Add(-2 * time.Minute),
		TestDuration:  time.Minute,
	}
	result := s.TimeStatusString()
	assert.Contains(t, result, "Test complete")

	// Testing phase, still in progress → progress message
	s = EvalStatus{
		Phase:         EvalPhaseTesting,
		TestStartTime: time.Now(),
		TestDuration:  time.Minute,
	}
	result = s.TimeStatusString()
	assert.Contains(t, result, "Progress")
	assert.Contains(t, result, "remaining")
}

// DevicePortConfig.MostlyEqual

func TestDevicePortConfigMostlyEqual(t *testing.T) {
	dpc1 := DevicePortConfig{
		Key: "k1",
		Ports: []NetworkPortConfig{
			{IfName: "eth0", Logicallabel: "wan0"},
		},
	}
	dpc2 := dpc1

	assert.True(t, dpc1.MostlyEqual(&dpc2))

	// Different key
	dpc2.Key = "k2"
	assert.False(t, dpc1.MostlyEqual(&dpc2))
	dpc2.Key = "k1"

	// Different port count
	dpc2.Ports = append(dpc2.Ports, NetworkPortConfig{IfName: "eth1"})
	assert.False(t, dpc1.MostlyEqual(&dpc2))
	dpc2.Ports = dpc2.Ports[:1]

	// Different IfName
	dpc2.Ports[0].IfName = "eth1"
	assert.False(t, dpc1.MostlyEqual(&dpc2))
	dpc2.Ports[0].IfName = "eth0"

	// Different IsMgmt
	dpc2.Ports[0].IsMgmt = true
	assert.False(t, dpc1.MostlyEqual(&dpc2))
}

// DevicePortConfig.MostlyEqual — remaining branches

func TestDevicePortConfigMostlyEqualRemainingBranches(t *testing.T) {
	base := DevicePortConfig{
		Key:   "k1",
		Ports: []NetworkPortConfig{{IfName: "eth0"}},
	}

	// DhcpConfig diff
	s2 := DevicePortConfig{Key: "k1", Ports: []NetworkPortConfig{{IfName: "eth0", DhcpConfig: DhcpConfig{Dhcp: DhcpTypeStatic}}}}
	assert.False(t, base.MostlyEqual(&s2))

	// L2LinkConfig.Equal returns false
	s3 := DevicePortConfig{Key: "k1", Ports: []NetworkPortConfig{{IfName: "eth0", L2LinkConfig: L2LinkConfig{L2Type: L2LinkTypeVLAN}}}}
	assert.False(t, base.MostlyEqual(&s3))

	// IgnoreDhcpNtpServers diff
	s4 := DevicePortConfig{Key: "k1", Ports: []NetworkPortConfig{{IfName: "eth0", IgnoreDhcpNtpServers: true}}}
	assert.False(t, base.MostlyEqual(&s4))

	// PNAC diff
	s5 := DevicePortConfig{Key: "k1", Ports: []NetworkPortConfig{{IfName: "eth0", PNAC: PNACConfig{Enabled: true}}}}
	assert.False(t, base.MostlyEqual(&s5))
}
