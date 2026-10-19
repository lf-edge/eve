// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test the life cycle of the vector.config global config item, i.e. how EVE
// accepts, promotes, rejects and reverts the configuration of Vector, its
// on-device log-processing pipeline.

package telemetry_test

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// The Vector configs are embedded instead of being read at run time: a test may
// be started from any directory, which makes relative paths unreliable.

//go:embed testdata/faulty.yaml
var faultyConfig []byte

//go:embed testdata/marker.yaml
var markerConfigTemplate []byte

const (
	// Placeholder in testdata/marker.yaml, substituted with a run-unique
	// sentinel by newMarkerConfig.
	markerSourcePlaceholder = "@MARKER_SOURCE@"

	// Prefix of the run-unique sentinel that the rendered marker config writes
	// into the `source` field of every uploaded log event.
	markerSourcePrefix = "evetest-vector-marker"

	// Source of log events that EVE uploads while running a Vector config which
	// does not rewrite `source`. zedagent logs continuously at the framework's
	// (debug) remote log level and base/logobjecttypes.go sets `source` to the
	// agent name, so such events are always available.
	vectorUnmarkedLogSource = "zedagent"

	// Substring of the message that pkg/vector's entrypoint logs when
	// `vector validate` rejects a config candidate. The Vector container's
	// output is ingested by newlogd like any other EVE service log, which makes
	// Vector's own verdict observable from the controller. Only the ASCII part
	// of the message is matched; it is surrounded by an emoji and an em dash.
	vectorRejectionLogMsg = "Candidate invalid"

	// A vector.config value that is not valid base64 at all, so it is rejected
	// by pillar's own validator before newlogd ever sees it.
	invalidVectorConfigValue = "not!base64!"
)

const (
	// liveVectorConfigPath is the config Vector actually runs. newlogd writes a
	// candidate next to it (vector.yaml.new) and pkg/vector's entrypoint
	// promotes the candidate to this path only after `vector validate` passes.
	liveVectorConfigPath = "/persist/vector/config/vector.yaml"

	// candidateVectorConfigPath is where newlogd writes a config it received
	// from the controller. pkg/vector's entrypoint consumes it either way: it is
	// renamed over the live config when it validates, and deleted when it does
	// not, so an absent candidate means it has been dealt with.
	candidateVectorConfigPath = "/persist/vector/config/vector.yaml.new"

	// defaultVectorConfigPath holds a copy of the Vector config built into the
	// EVE image, which newlogd restores whenever vector.config is empty.
	defaultVectorConfigPath = "/persist/vector/config/vector.yaml.default"
)

const (
	// Log events are batched into gzip bundles before upload, so waiting for a
	// particular event to reach the controller takes a while even with the fast
	// upload that the framework enables by default.
	vectorLogUploadTimeout = 10 * time.Minute

	// Promotion of a config candidate takes seconds (an inotify event, a
	// `vector validate` run and a rename), but it is gated on newlogd having
	// received the new global config first.
	vectorPromotionTimeout   = 5 * time.Minute
	vectorConfigPollInterval = 10 * time.Second

	// Polling interval for assertions that re-read the whole uploaded log
	// history on every attempt.
	vectorLogPollInterval = 15 * time.Second

	// How long the live Vector config must stay unchanged for a candidate to be
	// considered rejected rather than merely not promoted yet.
	vectorRejectionWindow = time.Minute

	// Device info carries the config item status; the framework configures EVE
	// to publish device info every 30 seconds.
	vectorDevInfoTimeout = 5 * time.Minute
)

// newMarkerConfig renders testdata/marker.yaml with a sentinel `source` value
// unique to this test run and returns both the sentinel and the rendered config.
//
// The marker config is a copy of EVE's Vector config with one added remap
// transform that overwrites the `source` field of every uploaded event.
// `source` is exposed by the controller for matching, which turns "is this
// config the one Vector runs?" into a question answerable from the controller
// alone, without inspecting the device. Being a standalone copy, it may drift
// from the config shipped in the image; all it has to remain is a config that
// `vector validate` accepts and that keeps both socket sinks wired up.
//
// The sentinel must be unique per run: with a fixed one, an uploaded event
// carrying it would also be produced by a marker config that an earlier test in
// the suite installed, or flushed late from Vector's disk buffer (which lives on
// /persist and survives a config reset), so it would no longer be evidence that
// *this* test's config push took effect.
func newMarkerConfig(t *WithT) (markerSource string, config []byte) {
	t.Expect(string(markerConfigTemplate)).To(ContainSubstring(markerSourcePlaceholder),
		"testdata/marker.yaml must contain the %s placeholder", markerSourcePlaceholder)
	markerSource = fmt.Sprintf("%s-%d", markerSourcePrefix, time.Now().UnixNano())
	config = bytes.ReplaceAll(markerConfigTemplate,
		[]byte(markerSourcePlaceholder), []byte(markerSource))
	return markerSource, config
}

// vectorConfigBase64 encodes a Vector config the way the vector.config item
// requires. It is the single encoding site, so a test that compares the value
// EVE reports back cannot drift from what vectorConfigItem sent.
func vectorConfigBase64(vectorConfig []byte) string {
	return base64.StdEncoding.EncodeToString(vectorConfig)
}

// vectorConfigItemRaw layers the vector.config global config item, carrying
// value verbatim, on top of the device configuration shared by this package.
// Only the test that pushes a value pillar has to reject needs this; anything
// that pushes an actual Vector config goes through vectorConfigItem.
//
// vector.enabled is set explicitly even though it already defaults to true:
// every assertion in this file depends on newlogd routing log events through
// Vector, so the test states that dependency instead of inheriting it. Never
// set it to false here: newlogd creates the Vector socket writers only if the
// flag was true when it started, but re-reads it for every log entry, so
// flipping it back to true at run time makes newlogd panic.
func vectorConfigItemRaw(value string) *evetest.EdgeDeviceConfig {
	devConfig := singleMgmtPortConfig()
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueBool(pillartypes.VectorEnabled, true)
	cfgProps.SetGlobalValueString(pillartypes.VectorConfig, value)
	devConfig.SetConfigProperties(cfgProps)
	return devConfig
}

// vectorConfigItem layers the vector.config global config item, carrying the
// given Vector config, on top of the device configuration shared by this
// package. An empty config clears the item.
func vectorConfigItem(vectorConfig []byte) *evetest.EdgeDeviceConfig {
	return vectorConfigItemRaw(vectorConfigBase64(vectorConfig))
}

// liveVectorConfigHash returns the SHA-256 digest of the Vector config that is
// currently promoted on the device.
func liveVectorConfigHash(device *evetest.EdgeDevice) (string, error) {
	content, err := device.ReadFile(liveVectorConfigPath)
	if err != nil {
		return "", err
	}
	return sha256Hex(content), nil
}

// defaultVectorConfigHash returns the digest of the Vector config built into the
// EVE image. pkg/vector's entrypoint copies it onto /persist at every container
// start and is its only writer, so it is an independent reference rather than a
// restatement of whatever is currently promoted.
func defaultVectorConfigHash(t *WithT, device *evetest.EdgeDevice) string {
	defaultConfig, err := device.ReadFile(defaultVectorConfigPath)
	t.Expect(err).ToNot(HaveOccurred(),
		"failed to read the image's default Vector config from the device")
	return sha256Hex(defaultConfig)
}

// expectLiveVectorConfigHash waits until the promoted Vector config hashes to
// wantHash, reporting description if it never does. A read failure gets its own
// message so that a transfer problem is not mistaken for the wrong config.
func expectLiveVectorConfigHash(t *WithT, device *evetest.EdgeDevice,
	wantHash, description string) {
	t.Eventually(func(g Gomega) {
		hash, err := liveVectorConfigHash(device)
		g.Expect(err).ToNot(HaveOccurred(),
			"failed to read the promoted Vector config from the device")
		g.Expect(hash).To(Equal(wantHash))
	}, vectorPromotionTimeout, vectorConfigPollInterval).Should(Succeed(), description)
}

// consistentlyLiveVectorConfig requires the promoted Vector config to keep
// hashing to wantHash for the whole rejection window, reporting description if
// it does not.
//
// Every sample shells out to scp, so a failed read is logged and retried on the
// next poll rather than failing the check - a transient transfer error must
// never be reported as the config having changed. Enough reads still have to
// succeed to span the window: the first poll fires immediately, so a run whose
// only successful read is that first one would report "unchanged for a whole
// minute" on the strength of a single sample taken before a promotion could
// plausibly have happened.
func consistentlyLiveVectorConfig(t *WithT, device *evetest.EdgeDevice,
	wantHash, description string) {
	// The window fits about six polls; requiring half of them leaves room for
	// transfer hiccups without letting the check shrink to a point.
	const minReads = 3
	log := evetest.Logger()
	var reads int
	t.Consistently(func(g Gomega) {
		hash, err := liveVectorConfigHash(device)
		if err != nil {
			log.Warnf("Failed to read %s, retrying: %v", liveVectorConfigPath, err)
			return
		}
		reads++
		g.Expect(hash).To(Equal(wantHash), description)
	}, vectorRejectionWindow, vectorConfigPollInterval).Should(Succeed())
	t.Expect(reads).To(BeNumerically(">=", minReads),
		"the promoted Vector config could be read only %d time(s) during the "+
			"%v window, too few for it to have been checked over that period",
		reads, vectorRejectionWindow)
}

// TestWorkingConfig verifies that a valid custom Vector config delivered through
// vector.config is promoted and actively processes the device log upload stream.
//
// The assertion is purely controller-side: the pushed config stamps every
// uploaded log event with a run-unique sentinel `source` (see newMarkerConfig),
// so a single uploaded event carrying that sentinel proves the config was
// accepted by pillar, validated and promoted by the Vector container, and is
// transforming events right now. That is strictly more than the on-device config
// file could show, which is why this test does not look at the device at all.
//
// There is deliberately no separate "Vector is running" check, because the
// assertion above subsumes it: with vector.enabled true newlogd has no bypass -
// it writes upload-path entries only to the Vector socket and drops them if that
// write fails - so any uploaded event proves Vector is running and forwarding,
// and one carrying the sentinel proves it is doing so through this config. A
// controller-side health check would not be available anyway: ZInfoDevice.tasks
// exists in eve-api but pillar never populates it, and domainmgr's per-process
// metrics do reach the controller inside ZMetricMsg.Pr carrying process names,
// but the framework exposes no accessor for them - EdgeDevice surfaces only the
// device, app, network-instance, volume and cluster metrics.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- log upload only needs working controller
//     connectivity over a single mgmt port.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps), logical label "ethernet0".
//   - vector.config set to the base64-encoded marker config.
//   - vector.enabled set to true (also its default).
//
// Phases / assertions
// -------------------
//  1. setup-done -> config-applied: subscribe to log events carrying the
//     sentinel source *before* pushing the config (a watch only delivers what
//     arrives after it was created), then push the marker config.
//  2. marker-observed: such an event reaches the controller. It is additionally
//     asserted to be a well-formed log record (non-empty content and severity),
//     so that a match cannot be an artifact of string filtering alone.
//
// No time-based guard is needed on the match: the sentinel is unique to this
// test run, so nothing but the config pushed here can produce it.
//
// Test params
// -----------
//   - HYPERVISOR, TPM. Neither is asserted on here; both are declared so that
//     every test in the suite states the same device requirements and the
//     framework can reuse one VM.
//
// Suite placement
// ---------------
//   - TestTelemetrySuite.
func TestWorkingConfig(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TPMParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()
	useTPM := evetest.GetTPMParameterValue()

	// Set up the test harness and specify the test prerequisites.
	device := setupTelemetryTestDevice(hypervisor, useTPM)
	log := evetest.Logger()
	evetest.Checkpoint("setup-done")

	// Build and apply the device configuration.
	markerSource, markerConfig := newMarkerConfig(t)
	markedLogs, stopLogWatch := device.WatchLogs(evetest.LogMsgMatch{
		Source: markerSource,
	})
	defer stopLogWatch()
	device.ApplyConfig(vectorConfigItem(markerConfig), true, true)
	evetest.Checkpoint("config-applied")
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(clusterNodeReadyTimeout)
	}

	// Phase 2: the promoted config stamps uploaded events with the sentinel.
	log.Infof("Waiting for an uploaded log event with source %q...", markerSource)
	var logMsg evetest.LogMsg
	t.Eventually(markedLogs, vectorLogUploadTimeout).Should(Receive(&logMsg),
		"no uploaded log event carried the sentinel source: the custom Vector "+
			"config was either not promoted or is not processing uploads")
	t.Expect(logMsg.Source).To(Equal(markerSource))
	t.Expect(logMsg.Message).ToNot(BeEmpty())
	t.Expect(logMsg.Severity).ToNot(BeEmpty())
	evetest.Checkpoint("marker-observed")
}

// TestFaultyConfig verifies that a Vector config which fails `vector validate`
// is never promoted, and that the previously promoted config keeps running.
//
// testdata/faulty.yaml is valid base64 and parses as YAML, so pillar stores it,
// but its dev_upload_socket sink lists a transform that the file leaves
// commented out. pkg/vector's entrypoint therefore fails to validate the
// candidate and deletes it instead of renaming it over the live config.
//
// Two independent signals are needed, because neither alone is conclusive:
//   - Vector's own verdict. The Vector container's output is ingested by newlogd
//     as device logs, so the message the entrypoint prints when it discards an
//     invalid candidate reaches the controller like any other log event. This is
//     the direct evidence that the validation gate ran and rejected this config,
//     and without it the test would also pass if the candidate had never been
//     written at all - the live config would be equally unchanged. It does rest
//     on the wording of a shell echo, which is why it is not the only signal.
//   - The content of the promoted config. "Marker-stamped events still arrive"
//     would hold even if the faulty config *had* been promoted: Vector refuses
//     to hot-reload a config it cannot validate and keeps serving the previous
//     one, the entrypoint does not restart it on a config change, and a Vector
//     that died would still flush its disk-backed sink buffer for a while. EVE
//     reports the promoted config to the controller in no form at all, hence the
//     file read, done through the framework's SCP-based ReadFile rather than raw
//     SSH, against the path that pkg/vector defines as the live config.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- log upload only needs working controller
//     connectivity over a single mgmt port.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps), logical label "ethernet0".
//   - vector.config set first to the marker config, then to the faulty config.
//   - vector.enabled set to true (also its default).
//
// Phases / assertions
// -------------------
//  1. marker-applied -> marker-active: push the marker config and wait for an
//     uploaded event carrying its run-unique sentinel source. Promoting a valid
//     custom config first is what stops "the live config did not change" in
//     phase 4 from being satisfied by a promotion path that never works.
//  2. faulty-applied: push the faulty config and wait until device info reports
//     vector.config holding exactly the faulty value. That the value survives
//     the round trip byte for byte is all this proves - it catches truncation in
//     transit, and nothing more. It is deliberately not asserted that the item
//     carries no error, which pillar's own validator cannot produce for a value
//     that is valid base64 by construction; newlogd's failures never reach the
//     item status either, so Vector's verdict has to be looked for in the logs.
//  3. faulty-rejected: Vector reports the candidate as invalid, queried from the
//     uploaded log history rather than a log watch, because this single entry
//     would be lost for good if the watch's stream reconnected. The filter pairs
//     the message with the sentinel source: on its way to the controller the
//     entry passes through the marker pipeline, which rewrites its source, so
//     matching both scopes it to this run and shows the marker pipeline was
//     still stamping at the moment of the rejection. The candidate file is then
//     required to be gone. That covers the cleanup only - the valid path renames
//     the candidate away and leaves it equally absent - so it corroborates
//     nothing about the rejection itself; the wording-independent evidence for
//     that is phase 4.
//  4. live-config-unchanged: the promoted config keeps hashing to the marker
//     config for the whole rejection window, which by then starts well after the
//     verdict of phase 3.
//  5. pipeline-alive: an event that arrives *after* the rejection has been
//     confirmed still carries the sentinel source. The watch is created here
//     rather than earlier for two reasons. While the marker config is promoted
//     its filter matches the device's entire log stream, so an earlier
//     subscription would fill its buffer and stall the reading of its own HTTP
//     body for the minutes that phases 3 and 4 take. And a watch created here
//     starts out empty, so the wait cannot be satisfied out of events buffered
//     before the rejection was confirmed - which also removes the need for a
//     timestamp guard, and with it a comparison between the host and device
//     clocks. This phase subsumes the "Vector is still running" check: newlogd
//     drops upload-path entries when the write to the Vector socket fails, so an
//     uploaded event proves Vector is forwarding.
//
// Test params
// -----------
//   - HYPERVISOR, TPM. Neither is asserted on here; both are declared so that
//     every test in the suite states the same device requirements and the
//     framework can reuse one VM.
//
// Suite placement
// ---------------
//   - TestTelemetrySuite.
func TestFaultyConfig(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TPMParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()
	useTPM := evetest.GetTPMParameterValue()

	// Set up the test harness and specify the test prerequisites.
	device := setupTelemetryTestDevice(hypervisor, useTPM)
	log := evetest.Logger()
	evetest.Checkpoint("setup-done")

	// Phase 1: establish a promoted custom config as the baseline.
	markerSource, markerConfig := installMarkerConfig(t, device)
	markerHash := sha256Hex(markerConfig)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(clusterNodeReadyTimeout)
	}

	// Phase 2: push the faulty config.
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(vectorConfigItem(faultyConfig), true, true)
	evetest.Checkpoint("faulty-applied")

	faultyBase64 := vectorConfigBase64(faultyConfig)
	t.Eventually(devUpdates, vectorDevInfoTimeout).Should(Receive(matchers.SatisfyPredicate(
		"EVE reports the faulty vector.config item back verbatim",
		func(devInfo *eveinfo.ZInfoDevice) bool {
			items := devInfo.GetConfigItemStatus().GetConfigItems()
			return items[string(pillartypes.VectorConfig)].GetValue() == faultyBase64
		})))

	// Phase 3: Vector itself rejects the candidate. Queried from the log history
	// rather than watched: each query re-reads everything, so a stream gap cannot
	// lose the one entry that carries the verdict.
	log.Infof("Waiting for Vector to report the candidate as invalid...")
	t.Eventually(func() []evetest.LogMsg {
		return device.GetLogs(evetest.LogMsgMatch{
			MsgHasSubstring: vectorRejectionLogMsg,
			Source:          markerSource,
		})
	}, vectorLogUploadTimeout, vectorLogPollInterval).ShouldNot(BeEmpty(),
		"Vector never reported the faulty candidate as invalid, so the "+
			"validation gate was not exercised")

	// A rejected candidate is also cleaned up. Absence alone does not imply
	// rejection - promotion removes the candidate too, by renaming it.
	t.Eventually(func() bool {
		return device.FileExists(candidateVectorConfigPath)
	}, vectorPromotionTimeout, vectorConfigPollInterval).Should(BeFalse(),
		"the rejected Vector config candidate was left behind on the device")
	evetest.Checkpoint("faulty-rejected")

	// Phase 4: and the rejected candidate never becomes the live config.
	log.Infof("Verifying that the promoted Vector config is left alone...")
	consistentlyLiveVectorConfig(t, device, markerHash,
		"the promoted Vector config changed: the faulty candidate was applied")
	evetest.Checkpoint("live-config-unchanged")

	// Phase 5: the marker pipeline still processes uploads. Subscribing only now
	// keeps the assertion about the present: with the marker config promoted this
	// filter matches every uploaded event, so an earlier subscription would both
	// stall its own stream and let an event buffered before the rejection satisfy
	// the wait.
	postPushLogs, stopPostPushWatch := device.WatchLogs(evetest.LogMsgMatch{
		Source: markerSource,
	})
	defer stopPostPushWatch()
	log.Infof("Verifying that the marker pipeline survived the faulty push...")
	t.Eventually(postPushLogs, vectorLogUploadTimeout).Should(Receive(),
		"no log event arrived with the sentinel source after the rejection: "+
			"the marker pipeline stopped processing uploads")
	evetest.Checkpoint("pipeline-alive")
}

// TestEmptyConfig verifies that clearing vector.config makes EVE restore the
// Vector config built into the image.
//
// The revert is observed twice, from both sides:
//   - Controller-side: uploaded events ingested after the clear carry their
//     original `source` again instead of the sentinel. This is a positive
//     assertion about identifiable events, not an argument from the absence of
//     sentinel events, which would be unsound - a dead pipeline uploads nothing
//     either, and Vector's disk-backed sink buffer keeps flushing already
//     stamped events for a while after a config change.
//   - On-device: the promoted config file becomes byte-identical to the
//     image's default config. This is what pins the outcome to *the default*
//     config rather than to any config that merely does not stamp events, and
//     EVE exposes no representation of the promoted Vector config to the
//     controller. The file is read through the framework's SCP-based ReadFile,
//     at the paths that pkg/vector's entrypoint defines. The reference copy is
//     not circular: the entrypoint rewrites it from the image on every start
//     and is its only writer.
//
// Because the framework clears all config items at setup, the device runs the
// default config by the time the test starts; the marker config is installed
// first so that the revert is an observable change.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- log upload only needs working controller
//     connectivity over a single mgmt port.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps), logical label "ethernet0".
//   - vector.config set to the marker config, then cleared.
//   - vector.enabled set to true (also its default).
//
// Phases / assertions
// -------------------
//  1. marker-applied -> marker-active: push the marker config and wait for an
//     uploaded event carrying its run-unique sentinel source. The marker config
//     and the image default must also differ, otherwise the revert would not be
//     observable.
//  2. empty-applied -> default-restored: clear vector.config and wait until the
//     promoted config file hashes to the image default.
//  3. real-source-restored: an event ingested after the clear reaches the
//     controller with source "zedagent", i.e. the running pipeline no longer
//     contains the marker transform and log uploads still work. The latter also
//     subsumes the "Vector is still running" check: newlogd drops upload-path
//     entries when the write to the Vector socket fails, so an uploaded event
//     proves Vector is forwarding.
//
// Test params
// -----------
//   - HYPERVISOR, TPM. Neither is asserted on here; both are declared so that
//     every test in the suite states the same device requirements and the
//     framework can reuse one VM.
//
// Suite placement
// ---------------
//   - TestTelemetrySuite.
func TestEmptyConfig(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TPMParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()
	useTPM := evetest.GetTPMParameterValue()

	// Set up the test harness and specify the test prerequisites.
	device := setupTelemetryTestDevice(hypervisor, useTPM)
	log := evetest.Logger()
	evetest.Checkpoint("setup-done")

	// Phase 1: install the marker config and confirm it is running. The default
	// config is captured beforehand, while it is still the promoted one.
	defaultHash := defaultVectorConfigHash(t, device)
	_, markerConfig := installMarkerConfig(t, device)
	t.Expect(sha256Hex(markerConfig)).ToNot(Equal(defaultHash),
		"the marker and the default Vector config must differ for the revert "+
			"to be observable")
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(clusterNodeReadyTimeout)
	}

	// Phase 2: clear vector.config. EVE keeps logging continuously, so the
	// watch for unmarked events can be created after the push - unlike a
	// one-shot trigger, the signal does not run out.
	clearVectorConfig(device)
	unmarkedLogs, stopLogWatch := device.WatchLogs(evetest.LogMsgMatch{
		Source:    vectorUnmarkedLogSource,
		NotBefore: time.Now(),
	})
	defer stopLogWatch()
	evetest.Checkpoint("empty-applied")

	log.Infof("Waiting for the live Vector config to revert to the default...")
	expectLiveVectorConfigHash(t, device, defaultHash,
		"the promoted Vector config did not revert to the image default")
	evetest.Checkpoint("default-restored")

	// Phase 3: uploaded events carry their original source again.
	log.Infof("Waiting for an uploaded log event with source %q...",
		vectorUnmarkedLogSource)
	t.Eventually(unmarkedLogs, vectorLogUploadTimeout).Should(Receive(),
		"no log event ingested after the clear carried its original source: "+
			"the marker transform is still in the pipeline, or uploads stopped")
	evetest.Checkpoint("real-source-restored")
}

// TestInvalidBase64Config verifies that a vector.config value which is not
// base64 at all is rejected by pillar and never reaches Vector.
//
// This is the first of the two gates a Vector config passes: pillar validates
// the item with base64Validator when it parses the config, long before newlogd
// writes a candidate and Vector validates the YAML. The tests that push real
// Vector configs never exercise it, because they encode their payload correctly
// by construction.
//
// Both halves are asserted, because a gate that drops the value silently and one
// that lets it through are both regressions and only the pair distinguishes
// them: EVE must report the item as unparsable, and the config Vector runs must
// not change. The second half needs the device to actually be running the image
// default when the invalid value is pushed, which the framework's config reset
// makes likely but does not guarantee - it waits for the device to fetch the
// cleared vector.config, not for Vector to have reloaded - so that is a
// precondition the test establishes rather than assumes.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- nothing here needs more than controller
//     connectivity over a single mgmt port.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps), logical label "ethernet0".
//   - vector.config set to a string that is not valid base64.
//   - vector.enabled set to true (also its default).
//
// Phases / assertions
// -------------------
//  1. default-config-running: wait until the promoted config hashes to the
//     image's default, so that a later change is attributable to this test.
//  2. invalid-config-applied -> invalid-config-rejected: push the invalid value
//     and wait until device info reports vector.config with a non-empty error.
//     The reported value is asserted *not* to be the pushed string: on a
//     validator failure pillar substitutes the previously live value, or the
//     item's default when there is none, and reports that instead.
//  3. live-config-unchanged: the promoted config keeps hashing to the image
//     default for the whole rejection window, i.e. the unparsable value never
//     made it as far as a config candidate.
//
// Test params
// -----------
//   - HYPERVISOR, TPM. Neither is asserted on here; both are declared so that
//     every test in the suite states the same device requirements and the
//     framework can reuse one VM.
//
// Suite placement
// ---------------
//   - TestTelemetrySuite.
func TestInvalidBase64Config(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TPMParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()
	useTPM := evetest.GetTPMParameterValue()

	// Set up the test harness and specify the test prerequisites.
	device := setupTelemetryTestDevice(hypervisor, useTPM)
	log := evetest.Logger()
	evetest.Checkpoint("setup-done")

	// Phase 1: establish the precondition.
	defaultHash := defaultVectorConfigHash(t, device)
	log.Infof("Waiting for the live Vector config to be the image default...")
	expectLiveVectorConfigHash(t, device, defaultHash,
		"the device does not run the image's default Vector config, so a later "+
			"change could not be attributed to the invalid value pushed here")
	evetest.Checkpoint("default-config-running")

	// Phase 2: push a value that is not base64.
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(vectorConfigItemRaw(invalidVectorConfigValue), true, true)
	evetest.Checkpoint("invalid-config-applied")
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(clusterNodeReadyTimeout)
	}

	t.Eventually(devUpdates, vectorDevInfoTimeout).Should(Receive(matchers.SatisfyPredicate(
		"EVE reports vector.config as unparsable and does not store the value",
		func(devInfo *eveinfo.ZInfoDevice) bool {
			items := devInfo.GetConfigItemStatus().GetConfigItems()
			item := items[string(pillartypes.VectorConfig)]
			return item.GetError() != "" &&
				item.GetValue() != invalidVectorConfigValue
		})))
	evetest.Checkpoint("invalid-config-rejected")

	// Phase 3: and it never reaches Vector.
	log.Infof("Verifying that the promoted Vector config is left alone...")
	consistentlyLiveVectorConfig(t, device, defaultHash,
		"the promoted Vector config changed: an unparsable vector.config value "+
			"reached Vector")
	evetest.Checkpoint("live-config-unchanged")
}
