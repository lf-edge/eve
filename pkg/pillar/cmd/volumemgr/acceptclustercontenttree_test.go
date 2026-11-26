// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestContentTreeNotLocallyUsable pins which content-tree states mean "a volume
// cannot be built from local content right now, so a volume whose PVC already
// exists should adopt it instead of waiting".
//
// The REMOTELOADED case is the one worth pinning deliberately: it sorts above
// LOADED numerically, so a plain "State < LOADED" test would call an
// accepted-from-PVC tree usable and send the volume down the path that looks
// the image up in CAS -- where it does not exist, because an accepted tree
// downloaded nothing.
func TestContentTreeNotLocallyUsable(t *testing.T) {
	cases := []struct {
		name string
		ct   *types.ContentTreeStatus
		want bool
	}{
		{"nil (no content tree published yet)", nil, true},
		{"INITIAL", &types.ContentTreeStatus{State: types.INITIAL}, true},
		{"DOWNLOADING", &types.ContentTreeStatus{State: types.DOWNLOADING}, true},
		{"VERIFIED but not loaded", &types.ContentTreeStatus{State: types.VERIFIED}, true},
		{"LOADED (real local content)", &types.ContentTreeStatus{State: types.LOADED}, false},
		{"CREATING_VOLUME", &types.ContentTreeStatus{State: types.CREATING_VOLUME}, false},
		{"REMOTELOADED (accepted from PVCs)", &types.ContentTreeStatus{State: types.REMOTELOADED}, true},
	}
	for _, c := range cases {
		if got := contentTreeNotLocallyUsable(c.ct); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestRemoteLoadedSortsAboveLoaded guards the assumption the previous test
// depends on: REMOTELOADED is numerically greater than LOADED, which is why it
// needs its own explicit check rather than falling out of a "< LOADED"
// comparison. If the enum is ever reordered this fails loudly here instead of
// silently changing which branch doUpdateVol takes.
func TestRemoteLoadedSortsAboveLoaded(t *testing.T) {
	if types.REMOTELOADED <= types.LOADED {
		t.Fatalf("REMOTELOADED (%d) is no longer above LOADED (%d); revisit contentTreeNotLocallyUsable",
			types.REMOTELOADED, types.LOADED)
	}
}

// TestContentTreeSatisfiedByPVCsNativeContainer pins that a content tree used
// by a native container volume is never accepted from its PVC: the pod runs
// the image from containerd and never reads the PVC, so skipping the download
// leaves the pod failing with ErrImageNeverPull.
func TestContentTreeSatisfiedByPVCsNativeContainer(t *testing.T) {
	for _, tc := range []struct {
		name            string
		nativeContainer bool
		want            bool
	}{
		{name: "native container needs the image", nativeContainer: true, want: false},
		{name: "VM disk is satisfied by its PVC", nativeContainer: false, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, pub := initVolumeModifyCtxForTest(t)
			ctx.hvTypeKube = true

			contentID := mustNewUUID(t)
			vc := types.VolumeConfig{
				VolumeID:          mustNewUUID(t),
				ContentID:         contentID,
				IsNativeContainer: tc.nativeContainer,
			}
			pvcName := vc.GetPVCName()
			pvcAdoptCache[pvcName] = pvcAdoptCacheEntry{state: kubeapi.PVCStateReady, checked: time.Now()}
			t.Cleanup(func() { delete(pvcAdoptCache, pvcName) })
			publishTestVolumeConfig(t, ctx, pub, vc)

			status := &types.ContentTreeStatus{ContentID: contentID}
			if got := contentTreeSatisfiedByPVCs(ctx, status); got != tc.want {
				t.Errorf("contentTreeSatisfiedByPVCs() = %v, want %v", got, tc.want)
			}
		})
	}
}

// restartableSub lets a test flip Restarted(): MemoryDriver's Restart is a
// no-op, so SignalRestarted never reaches the subscriber.
type restartableSub struct {
	pubsub.Subscription
	restarted bool
}

func (s *restartableSub) Restarted() bool { return s.restarted }

// TestContentTreeWaitsForVolumeConfigRestart pins the EVE-k gate in
// doUpdateContentTree: after a reboot DatastoreConfig can resolve before
// zedagent's VolumeConfig set arrives, and a tree whose blob is still verified
// on disk must not run ahead to LOADING while contentTreeSatisfiedByPVCs
// cannot yet see the volume whose PVC already satisfies it.
func TestContentTreeWaitsForVolumeConfigRestart(t *testing.T) {
	ctx, pub := initVolumeModifyCtxForTest(t)
	ctx.hvTypeKube = true
	sub := &restartableSub{Subscription: ctx.subVolumeConfig}
	ctx.subVolumeConfig = sub

	contentID := mustNewUUID(t)
	status := &types.ContentTreeStatus{
		ContentID:             contentID,
		State:                 types.INITIAL,
		AllDatastoresResolved: true,
	}
	changed, done := doUpdateContentTree(ctx, status)
	if changed || done || status.State != types.INITIAL {
		t.Fatalf("before VolumeConfig restart: got changed=%v done=%v state=%v, want false/false/INITIAL",
			changed, done, status.State)
	}

	vc := types.VolumeConfig{VolumeID: mustNewUUID(t), ContentID: contentID}
	pvcName := vc.GetPVCName()
	pvcAdoptCache[pvcName] = pvcAdoptCacheEntry{state: kubeapi.PVCStateReady, checked: time.Now()}
	t.Cleanup(func() { delete(pvcAdoptCache, pvcName) })
	publishTestVolumeConfig(t, ctx, pub, vc)
	sub.restarted = true

	doUpdateContentTree(ctx, status)
	if status.State != types.REMOTELOADED {
		t.Fatalf("after VolumeConfig restart: state %v, want REMOTELOADED", status.State)
	}
}
