// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"

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
