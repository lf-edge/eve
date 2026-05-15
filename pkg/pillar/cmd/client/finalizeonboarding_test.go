// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

func newOnboardPublication(t *testing.T) pubsub.Publication {
	t.Helper()
	ps := pubsub.New(pubsub.NewMemoryDriver(), logrus.StandardLogger(), log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "client_test",
		TopicType: types.OnboardingStatus{},
	})
	if err != nil {
		t.Fatalf("NewPublication: %v", err)
	}
	return pub
}

func newFinalizeCtx(t *testing.T) (*clientContext, *fakeHostnameSetter, string) {
	t.Helper()
	dir := t.TempDir()
	hs := &fakeHostnameSetter{}
	ctx := &clientContext{
		hostnameSetter:        hs,
		uuidFileName:          filepath.Join(dir, "uuid"),
		hardwaremodelFileName: filepath.Join(dir, "hardwaremodel"),
	}
	return ctx, hs, dir
}

func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	u, err := uuid.FromString(s)
	if err != nil {
		t.Fatalf("uuid.FromString(%s): %v", s, err)
	}
	return u
}

func TestFinalizeOnboarding_NilUUIDIsNoop(t *testing.T) {
	ctx, hs, dir := newFinalizeCtx(t)
	pub := newOnboardPublication(t)

	ctx.finalizeOnboarding(nilUUID, nilUUID, "", "", pub)

	if len(hs.calls) != 0 {
		t.Errorf("hostname calls = %v, want 0 for nil UUID", hs.calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "uuid")); err == nil {
		t.Error("uuid file written for nil UUID")
	}
}

func TestFinalizeOnboarding_FirstOnboardWritesAllArtefacts(t *testing.T) {
	const newUUID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	ctx, hs, dir := newFinalizeCtx(t)
	pub := newOnboardPublication(t)

	devUUID := mustUUID(t, newUUID)
	ctx.finalizeOnboarding(devUUID, nilUUID, "Dell.PowerEdge R740", "", pub)

	if len(hs.calls) != 1 || hs.calls[0] != newUUID {
		t.Errorf("hostname calls = %v, want [%s]", hs.calls, newUUID)
	}
	got, err := os.ReadFile(filepath.Join(dir, "uuid"))
	if err != nil {
		t.Fatalf("read uuid file: %v", err)
	}
	if string(got) != newUUID+"\n" {
		t.Errorf("uuid file = %q, want %q", got, newUUID+"\n")
	}
	gotModel, err := os.ReadFile(filepath.Join(dir, "hardwaremodel"))
	if err != nil {
		t.Fatalf("read hardwaremodel file: %v", err)
	}
	if string(gotModel) != "Dell.PowerEdge R740" {
		t.Errorf("hardwaremodel file = %q", gotModel)
	}
	itm, err := pub.Get("global")
	if err != nil {
		t.Fatalf("pub.Get global: %v", err)
	}
	status := itm.(types.OnboardingStatus)
	if status.DeviceUUID != devUUID {
		t.Errorf("published UUID = %s, want %s", status.DeviceUUID, devUUID)
	}
	if status.HardwareModel != "Dell.PowerEdge R740" {
		t.Errorf("published model = %q", status.HardwareModel)
	}
}

func TestFinalizeOnboarding_UnchangedUUIDSkipsFileWriteWhenFileExists(t *testing.T) {
	const goodUUID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	ctx, _, dir := newFinalizeCtx(t)
	pub := newOnboardPublication(t)

	// Pre-create the uuid file with stale contents to detect overwrite.
	preExisting := []byte("stale\n")
	if err := os.WriteFile(filepath.Join(dir, "uuid"), preExisting, 0644); err != nil {
		t.Fatalf("seed uuid: %v", err)
	}
	// Allow filesystem timestamp granularity to register.
	time.Sleep(20 * time.Millisecond)

	devUUID := mustUUID(t, goodUUID)
	ctx.finalizeOnboarding(devUUID, devUUID /* unchanged */, "", "", pub)

	got, _ := os.ReadFile(filepath.Join(dir, "uuid"))
	if string(got) != string(preExisting) {
		t.Errorf("uuid file was overwritten: got %q, want unchanged %q", got, preExisting)
	}
}

func TestFinalizeOnboarding_HardwaremodelUnchangedSkipsWrite(t *testing.T) {
	const goodUUID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	ctx, _, dir := newFinalizeCtx(t)
	pub := newOnboardPublication(t)

	devUUID := mustUUID(t, goodUUID)
	ctx.finalizeOnboarding(devUUID, devUUID, "Dell.X", "Dell.X" /* unchanged */, pub)

	if _, err := os.Stat(filepath.Join(dir, "hardwaremodel")); err == nil {
		t.Error("hardwaremodel file written when model unchanged")
	}
}

func TestFinalizeOnboarding_HostnameSetterFailureDoesNotPanic(t *testing.T) {
	const goodUUID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	ctx, hs, _ := newFinalizeCtx(t)
	pub := newOnboardPublication(t)
	hs.err = os.ErrPermission

	devUUID := mustUUID(t, goodUUID)
	ctx.finalizeOnboarding(devUUID, nilUUID, "Dell.X", "", pub)

	// Despite the setter failing, OnboardingStatus must still be published.
	if _, err := pub.Get("global"); err != nil {
		t.Errorf("OnboardingStatus not published after hostname failure: %v", err)
	}
}
