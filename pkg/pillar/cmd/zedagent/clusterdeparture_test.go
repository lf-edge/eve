// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"testing"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// present reports whether key is currently published in pub.
func present(pub interface {
	Get(string) (interface{}, error)
}, key string) bool {
	_, err := pub.Get(key)
	return err == nil
}

// TestClusterDepartingSuppressesDeletion is the core regression test for the
// ENC "replace node" data-loss bug: while this node is leaving the cluster
// (getconfigContext.clusterDeparting set), zedagent must NOT unpublish the
// AppInstanceConfig / VolumeConfig / ContentTreeConfig that the controller
// dropped from config -- otherwise volumemgr deletes the still-shared PVC before
// the node reboots into single-node mode. With the flag clear, the same removal
// must delete as before.
func TestClusterDepartingSuppressesDeletion(t *testing.T) {
	getconfigCtx, _ := newFuzzGetConfigCtx(t)

	// parseAppInstanceConfig bails out early on an empty device UUID, so the
	// "empty config" we feed still needs a valid Id for its delete loop to run.
	validID := &zconfig.UUIDandVersion{
		Uuid:    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		Version: "1",
	}
	emptyConfig := &zconfig.EdgeDevConfig{Id: validID}

	appCfg := types.AppInstanceConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: uuid.Must(uuid.NewV4())},
	}
	volCfg := types.VolumeConfig{VolumeID: uuid.Must(uuid.NewV4())}
	ctCfg := types.ContentTreeConfig{ContentID: uuid.Must(uuid.NewV4())}

	mustPublish(t, getconfigCtx.pubAppInstanceConfig, appCfg.Key(), appCfg)
	mustPublish(t, getconfigCtx.pubVolumeConfig, volCfg.Key(), volCfg)
	mustPublish(t, getconfigCtx.pubContentTreeConfig, ctCfg.Key(), ctCfg)

	// The per-section SHA caches short-circuit re-parsing an unchanged subtree;
	// reset them so each parse call below actually runs its delete loop.
	resetHashes := func() {
		appinstancePrevConfigHash = nil
		volumeHash = nil
		contentInfoHash = nil
	}
	parseAll := func() {
		resetHashes()
		parseAppInstanceConfig(getconfigCtx, emptyConfig)
		parseVolumeConfig(getconfigCtx, emptyConfig)
		parseContentInfoConfig(getconfigCtx, emptyConfig)
	}

	// Phase 1: departing -> deletions suppressed, all items remain published.
	getconfigCtx.clusterDeparting = true
	parseAll()
	if !present(getconfigCtx.pubAppInstanceConfig, appCfg.Key()) {
		t.Error("AppInstanceConfig was removed while cluster departing")
	}
	if !present(getconfigCtx.pubVolumeConfig, volCfg.Key()) {
		t.Error("VolumeConfig was removed while cluster departing")
	}
	if !present(getconfigCtx.pubContentTreeConfig, ctCfg.Key()) {
		t.Error("ContentTreeConfig was removed while cluster departing")
	}

	// Phase 2: not departing -> the same removal deletes as before.
	getconfigCtx.clusterDeparting = false
	parseAll()
	if present(getconfigCtx.pubAppInstanceConfig, appCfg.Key()) {
		t.Error("AppInstanceConfig should have been removed when not departing")
	}
	if present(getconfigCtx.pubVolumeConfig, volCfg.Key()) {
		t.Error("VolumeConfig should have been removed when not departing")
	}
	if present(getconfigCtx.pubContentTreeConfig, ctCfg.Key()) {
		t.Error("ContentTreeConfig should have been removed when not departing")
	}
}

// TestCancelClusterDepartureReconcilesSuppressed is a regression test for the
// cancel path: after a departure push suppressed removed items (which latched the
// per-subtree SHA caches to the empty-config hash), an aborted replace that
// leaves the items absent must still delete them in the same pass. Without
// cancelClusterDeparture invalidating the SHA caches, the parsers short-circuit
// on the unchanged subtree and the suppressed items linger forever (no reboot
// wipes them on a cancelled departure). It deliberately does NOT reset the hash
// caches between phases, unlike TestClusterDepartingSuppressesDeletion.
func TestCancelClusterDepartureReconcilesSuppressed(t *testing.T) {
	getconfigCtx, _ := newFuzzGetConfigCtx(t)

	validID := &zconfig.UUIDandVersion{
		Uuid:    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		Version: "1",
	}
	emptyConfig := &zconfig.EdgeDevConfig{Id: validID}

	appCfg := types.AppInstanceConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: uuid.Must(uuid.NewV4())},
	}
	volCfg := types.VolumeConfig{VolumeID: uuid.Must(uuid.NewV4())}
	ctCfg := types.ContentTreeConfig{ContentID: uuid.Must(uuid.NewV4())}
	mustPublish(t, getconfigCtx.pubAppInstanceConfig, appCfg.Key(), appCfg)
	mustPublish(t, getconfigCtx.pubVolumeConfig, volCfg.Key(), volCfg)
	mustPublish(t, getconfigCtx.pubContentTreeConfig, ctCfg.Key(), ctCfg)

	// Departure push: items removed from config but suppressed. This latches the
	// per-subtree SHA caches to the empty-config hash (reset once here to ensure
	// the first parse runs, mimicking a real subtree change).
	appinstancePrevConfigHash = nil
	volumeHash = nil
	contentInfoHash = nil
	getconfigCtx.clusterDeparting = true
	parseAppInstanceConfig(getconfigCtx, emptyConfig)
	parseVolumeConfig(getconfigCtx, emptyConfig)
	parseContentInfoConfig(getconfigCtx, emptyConfig)
	if !present(getconfigCtx.pubAppInstanceConfig, appCfg.Key()) {
		t.Fatal("precondition: app should be suppressed during departure")
	}

	// Cancel (cluster restored, items still absent) WITHOUT touching the hash
	// caches -- exactly as production does -- then re-run the parsers as they would
	// run later in the same parseConfig pass. The items must now be deleted.
	cancelClusterDeparture(getconfigCtx)
	parseAppInstanceConfig(getconfigCtx, emptyConfig)
	parseVolumeConfig(getconfigCtx, emptyConfig)
	parseContentInfoConfig(getconfigCtx, emptyConfig)

	if present(getconfigCtx.pubAppInstanceConfig, appCfg.Key()) {
		t.Error("AppInstanceConfig should be deleted after cancel with item still absent")
	}
	if present(getconfigCtx.pubVolumeConfig, volCfg.Key()) {
		t.Error("VolumeConfig should be deleted after cancel with item still absent")
	}
	if present(getconfigCtx.pubContentTreeConfig, ctCfg.Key()) {
		t.Error("ContentTreeConfig should be deleted after cancel with item still absent")
	}
}

// TestVolumeGenCounterBumpNotSuppressed verifies that a generation-counter bump
// (an in-place volume replace, not a cluster departure) is still applied
// immediately even while departing -- only the true-removal case is held back.
func TestVolumeGenCounterBumpNotSuppressed(t *testing.T) {
	getconfigCtx, _ := newFuzzGetConfigCtx(t)

	volID := uuid.Must(uuid.NewV4())
	oldCfg := types.VolumeConfig{VolumeID: volID, GenerationCounter: 1}
	mustPublish(t, getconfigCtx.pubVolumeConfig, oldCfg.Key(), oldCfg)

	// Same volume UUID, higher generation counter -> replace, not departure.
	newConfig := &zconfig.EdgeDevConfig{
		Id: &zconfig.UUIDandVersion{Uuid: "6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
		Volumes: []*zconfig.Volume{{
			Uuid:            volID.String(),
			GenerationCount: 2,
		}},
	}

	getconfigCtx.clusterDeparting = true
	volumeHash = nil
	parseVolumeConfig(getconfigCtx, newConfig)

	// The stale gen-counter-1 entry must be gone despite departing.
	if present(getconfigCtx.pubVolumeConfig, oldCfg.Key()) {
		t.Error("stale generation-counter VolumeConfig should be replaced even while departing")
	}
}

// TestPublishEmptyENCCArmsDeparture covers the departure-edge detection: on a
// kube node, a genuine departure (isDeparture=true) after having been in a
// valid cluster arms clusterDeparting; never having been in a valid cluster,
// or a non-kube node, must not arm it.
func TestPublishEmptyENCCArmsDeparture(t *testing.T) {
	getconfigCtx, _ := newFuzzGetConfigCtx(t)
	zedagentCtx := getconfigCtx.zedagentCtx

	// kube node, previously in a valid cluster, genuine departure -> armed.
	zedagentCtx.hvTypeKube = true
	getconfigCtx.wasInValidCluster = true
	getconfigCtx.clusterDeparting = false
	publishEmptyENCC(zedagentCtx, true)
	if !getconfigCtx.clusterDeparting {
		t.Error("expected clusterDeparting=true after a genuine departure from a valid cluster on a kube node")
	}

	// never been in a valid cluster -> no arming.
	getconfigCtx.wasInValidCluster = false
	getconfigCtx.clusterDeparting = false
	publishEmptyENCC(zedagentCtx, true)
	if getconfigCtx.clusterDeparting {
		t.Error("did not expect arming when the node was not previously in a valid cluster")
	}

	// non-kube node -> never arm, even from a valid cluster.
	zedagentCtx.hvTypeKube = false
	getconfigCtx.wasInValidCluster = true
	getconfigCtx.clusterDeparting = false
	publishEmptyENCC(zedagentCtx, true)
	if getconfigCtx.clusterDeparting {
		t.Error("did not expect arming on a non-kube node")
	}

	// kube node, previously valid, but this is a local parse-error recovery
	// call (isDeparture=false), not a genuine controller-initiated departure ->
	// must never arm, and must leave wasInValidCluster untouched so a later
	// genuine departure still arms.
	zedagentCtx.hvTypeKube = true
	getconfigCtx.wasInValidCluster = true
	getconfigCtx.clusterDeparting = false
	publishEmptyENCC(zedagentCtx, false)
	if getconfigCtx.clusterDeparting {
		t.Error("did not expect arming from a parse-error recovery call (isDeparture=false)")
	}
	if !getconfigCtx.wasInValidCluster {
		t.Error("a parse-error recovery call must not clear wasInValidCluster")
	}
}

// TestPublishEmptyENCCParseErrorDoesNotDefeatArming is the regression test for
// the arming-defeated-by-parse-error-latch bug flagged in review: before
// wasInValidCluster existed, arming was inferred from the last *published*
// ENCC's Valid field, which the isDeparture=false parse-error paths also set
// to false. A transient parse error (bad CIDR/JoinServerIP/ClusterId/cipher
// token/tie-breaker UUID) landing between a valid cluster push and a genuine
// departure push would silently poison that signal, so the genuine departure
// right after it would fail to arm -- reintroducing the app/volume/PVC
// data-loss this mechanism exists to prevent.
func TestPublishEmptyENCCParseErrorDoesNotDefeatArming(t *testing.T) {
	getconfigCtx, _ := newFuzzGetConfigCtx(t)
	zedagentCtx := getconfigCtx.zedagentCtx
	zedagentCtx.hvTypeKube = true

	// Push N: valid cluster.
	getconfigCtx.wasInValidCluster = true
	getconfigCtx.clusterDeparting = false

	// Push N+1: transient parse error (e.g. cipher decrypt failure) -- not a
	// departure; must not arm, and must not clear wasInValidCluster.
	publishEmptyENCC(zedagentCtx, false)
	if getconfigCtx.clusterDeparting {
		t.Fatal("parse-error recovery call armed clusterDeparting")
	}

	// Push N+2: genuine departure -- must still arm despite the N+1 blip.
	publishEmptyENCC(zedagentCtx, true)
	if !getconfigCtx.clusterDeparting {
		t.Error("genuine departure after a transient parse-error blip failed to arm; " +
			"a parse error must not be able to defeat departure-suppression arming")
	}
}

// TestClusterDepartureWiredThroughEntryPoint drives the real entry point instead
// of poking each half of the mechanism by hand: it feeds parseEdgeNodeClusterConfig
// a config whose GetCluster()==nil (the actual controller signal for a departure),
// and confirms both that this arms clusterDeparting and that the same pass's
// parseVolumeConfig then suppresses the volume's removal. The other tests in this
// file arm via a direct publishEmptyENCC(ctx, true) call and suppress via a direct
// clusterDeparting = true assignment; neither exercises the GetCluster()==nil ->
// publishEmptyENCC wiring inside parseEdgeNodeClusterConfig itself.
func TestClusterDepartureWiredThroughEntryPoint(t *testing.T) {
	getconfigCtx, _ := newFuzzGetConfigCtx(t)
	zedagentCtx := getconfigCtx.zedagentCtx
	zedagentCtx.hvTypeKube = true
	getconfigCtx.wasInValidCluster = true
	getconfigCtx.clusterDeparting = false

	volCfg := types.VolumeConfig{VolumeID: uuid.Must(uuid.NewV4())}
	mustPublish(t, getconfigCtx.pubVolumeConfig, volCfg.Key(), volCfg)

	// A config push with the cluster section dropped (GetCluster()==nil) and the
	// volume gone too -- the real shape of a controller-initiated node-replace.
	validID := &zconfig.UUIDandVersion{
		Uuid:    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		Version: "1",
	}
	emptyConfig := &zconfig.EdgeDevConfig{Id: validID}

	parseEdgeNodeClusterConfig(getconfigCtx, emptyConfig)
	if !getconfigCtx.clusterDeparting {
		t.Fatal("parseEdgeNodeClusterConfig with GetCluster()==nil did not arm clusterDeparting")
	}

	volumeHash = nil
	parseVolumeConfig(getconfigCtx, emptyConfig)
	if !present(getconfigCtx.pubVolumeConfig, volCfg.Key()) {
		t.Error("VolumeConfig was removed even though clusterDeparting was armed " +
			"via the real parseEdgeNodeClusterConfig entry point")
	}
}

// validClusterConfig returns a well-formed EdgeDevConfig carrying a Cluster
// section that parseEdgeNodeClusterConfig can parse end-to-end without hitting
// any of its error paths (valid CIDR, valid JoinServerIP, valid ClusterId UUID,
// no tie breaker, no encrypted token).
func validClusterConfig() *zconfig.EdgeDevConfig {
	return &zconfig.EdgeDevConfig{
		Id: &zconfig.UUIDandVersion{
			Uuid:    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			Version: "1",
		},
		Cluster: &zconfig.EdgeNodeCluster{
			ClusterName:      "test-cluster",
			ClusterId:        "7c9e6679-7425-40de-944b-e07fc1f90ae7",
			ClusterInterface: "eth0",
			ClusterIpPrefix:  "192.168.1.10/24",
			JoinServerIp:     "192.168.1.1",
		},
	}
}

// TestParseEdgeNodeClusterConfigHappyPath covers the success path of
// parseEdgeNodeClusterConfig, which until now had zero direct coverage: every
// existing test in this file only ever fed it a config with GetCluster()==nil
// (the departure/error edge) or drove the arming/suppression logic by calling
// publishEmptyENCC / setting clusterDeparting directly. This confirms a
// well-formed Cluster section parses successfully -- publishing
// Valid:true and Initialized:true, and setting wasInValidCluster -- without
// touching clusterDeparting.
func TestParseEdgeNodeClusterConfigHappyPath(t *testing.T) {
	getconfigCtx, _ := newFuzzGetConfigCtx(t)
	zedagentCtx := getconfigCtx.zedagentCtx
	zedagentCtx.hvTypeKube = true
	getconfigCtx.wasInValidCluster = false
	getconfigCtx.clusterDeparting = false

	parseEdgeNodeClusterConfig(getconfigCtx, validClusterConfig())

	if getconfigCtx.clusterDeparting {
		t.Error("a successful cluster parse must not arm clusterDeparting")
	}
	if !getconfigCtx.wasInValidCluster {
		t.Error("a successful cluster parse must set wasInValidCluster")
	}
	published, err := zedagentCtx.pubEdgeNodeClusterConfig.Get("global")
	if err != nil {
		t.Fatalf("EdgeNodeClusterConfig was not published: %v", err)
	}
	encc := published.(types.EdgeNodeClusterConfig)
	if !encc.Initialized || !encc.Valid {
		t.Errorf("expected Initialized=true, Valid=true, got %+v", encc)
	}
	if encc.ClusterName != "test-cluster" {
		t.Errorf("expected ClusterName %q, got %q", "test-cluster", encc.ClusterName)
	}
}

// TestClusterRestoreCancelsDepartureThroughEntryPoint drives the restore/cancel
// half of the mechanism through the same real entry point as
// TestClusterDepartureWiredThroughEntryPoint drives the departure half.
// TestCancelClusterDepartureReconcilesSuppressed calls cancelClusterDeparture
// directly by hand; this instead feeds parseEdgeNodeClusterConfig a valid
// Cluster config while clusterDeparting is armed, and confirms that the
// "cluster restored -> cancel departure" branch inside parseEdgeNodeClusterConfig
// itself fires and reconciles a volume that was suppressed-but-removed.
func TestClusterRestoreCancelsDepartureThroughEntryPoint(t *testing.T) {
	getconfigCtx, _ := newFuzzGetConfigCtx(t)
	zedagentCtx := getconfigCtx.zedagentCtx
	zedagentCtx.hvTypeKube = true
	getconfigCtx.wasInValidCluster = true
	getconfigCtx.clusterDeparting = true

	// A volume that was suppressed-but-removed while departing: absent from
	// config, but still published because clusterDeparting held it back.
	volCfg := types.VolumeConfig{VolumeID: uuid.Must(uuid.NewV4())}
	mustPublish(t, getconfigCtx.pubVolumeConfig, volCfg.Key(), volCfg)
	volumeHash = nil
	parseVolumeConfig(getconfigCtx, &zconfig.EdgeDevConfig{Id: validClusterConfig().Id})
	if !present(getconfigCtx.pubVolumeConfig, volCfg.Key()) {
		t.Fatal("precondition: volume should still be suppressed while departing")
	}

	// The cluster is restored (real, valid Cluster config); the entry point must
	// cancel departure suppression, and the still-empty volume subtree must then
	// be reconciled away in the same parseConfig pass.
	parseEdgeNodeClusterConfig(getconfigCtx, validClusterConfig())
	if getconfigCtx.clusterDeparting {
		t.Error("parseEdgeNodeClusterConfig with a valid Cluster config did not cancel clusterDeparting")
	}

	parseVolumeConfig(getconfigCtx, validClusterConfig())
	if present(getconfigCtx.pubVolumeConfig, volCfg.Key()) {
		t.Error("VolumeConfig should have been reconciled away after the real restore/cancel path ran")
	}
}
