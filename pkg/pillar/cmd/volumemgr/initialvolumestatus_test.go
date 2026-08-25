// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func TestGetVolumeStatusByPVC(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	pvcName := fmt.Sprintf("%s-pvc-3", id.String())

	vs, err := getVolumeStatusByPVC(pvcName)
	assert.NoError(t, err)
	assert.Equal(t, id, vs.VolumeID)
	assert.Equal(t, int64(3), vs.GenerationCounter)
	assert.Equal(t, pvcName, vs.FileLocation)
	// getPVCList/getVolumeStatusByPVC cannot recover LocalGenerationCounter
	// from the PVC name alone, so GetPVCName must round-trip against the
	// GenerationCounter this parsed - otherwise volumesToReap would compute
	// the wrong Key() and reap a live volume.
	assert.Equal(t, pvcName, vs.GetPVCName())
}

func TestGetVolumeStatusByPVCInvalid(t *testing.T) {
	cases := []string{
		"not-a-uuid-pvc-3",
		"11111111-1111-1111-1111-111111111111-pvc-notanumber",
		"11111111-1111-1111-1111-111111111111", // no "-pvc-" separator
	}
	for _, name := range cases {
		_, err := getVolumeStatusByPVC(name)
		assert.Error(t, err, "expected an error for PVC name %q", name)
	}
}

// TestVolumesToReapSkipsLiveVolume pins the safety property this whole
// change depends on: a volume this node still tracks - including one it
// tracks only because it is a failover candidate for an app running
// elsewhere in the cluster, not because it is unused - must never be
// reaped, regardless of what resolve() reconstructs from its name alone.
func TestVolumesToReapSkipsLiveVolume(t *testing.T) {
	ctx := initStatusCtx(t)
	live := types.VolumeStatus{
		VolumeID:          uuid.Must(uuid.NewV4()),
		GenerationCounter: 0,
	}
	publishVolumeStatus(&ctx, &live)

	pvcName := live.GetPVCName()
	reap := volumesToReap(&ctx, []string{pvcName}, getVolumeStatusByPVC)
	assert.Empty(t, reap, "a currently-published volume must never be reaped")
}

// TestVolumesToReapSkipsLiveVolumeWithLocalGeneration shows why
// getVolumeStatusByPVC can assume LocalGenerationCounter is zero.
//
// A PVC name carries one number, not two. The reconstruction puts it all in
// GenerationCounter, which is a different split than the live volume uses.
// Key() and GetPVCName() both use the sum of the two counters, so gen=2/local=3
// and gen=5/local=0 produce the same key. If either function starts to use the
// counters apart, this test fails, and a live volume would be reaped.
func TestVolumesToReapSkipsLiveVolumeWithLocalGeneration(t *testing.T) {
	ctx := initStatusCtx(t)
	live := types.VolumeStatus{
		VolumeID:               uuid.Must(uuid.NewV4()),
		GenerationCounter:      2,
		LocalGenerationCounter: 3,
	}
	publishVolumeStatus(&ctx, &live)

	pvcName := live.GetPVCName()
	// The name must carry the sum, not either counter on its own.
	assert.Equal(t, fmt.Sprintf("%s-pvc-5", live.VolumeID.String()), pvcName)

	rebuilt, err := getVolumeStatusByPVC(pvcName)
	assert.NoError(t, err)
	assert.Equal(t, live.Key(), rebuilt.Key(),
		"the key rebuilt from a PVC name must match the live volume's, "+
			"whatever split of generation counters produced it")

	reap := volumesToReap(&ctx, []string{pvcName}, getVolumeStatusByPVC)
	assert.Empty(t, reap,
		"a live volume with a non-zero LocalGenerationCounter must never be reaped")
}

// TestVolumesToReapIncludesSupersededGeneration covers the purge case. The app
// moved to a new generation. No published VolumeStatus names the old PVC, so
// the pass reaps that one only.
func TestVolumesToReapIncludesSupersededGeneration(t *testing.T) {
	ctx := initStatusCtx(t)
	volID := uuid.Must(uuid.NewV4())
	live := types.VolumeStatus{
		VolumeID:          volID,
		GenerationCounter: 1,
	}
	publishVolumeStatus(&ctx, &live)

	stale := types.VolumeStatus{
		VolumeID:          volID,
		GenerationCounter: 0,
	}
	reap := volumesToReap(&ctx,
		[]string{stale.GetPVCName(), live.GetPVCName()}, getVolumeStatusByPVC)
	assert.Len(t, reap, 1)
	assert.Equal(t, stale.GetPVCName(), reap[0].FileLocation,
		"only the superseded generation's PVC may be reaped")
}

// TestVolumesToReapIncludesUnknownVolume is the positive case: a candidate
// with no published VolumeStatus at all is exactly what this pass exists to
// find.
func TestVolumesToReapIncludesUnknownVolume(t *testing.T) {
	ctx := initStatusCtx(t)
	orphanID := uuid.Must(uuid.NewV4())
	pvcName := fmt.Sprintf("%s-pvc-0", orphanID.String())

	reap := volumesToReap(&ctx, []string{pvcName}, getVolumeStatusByPVC)
	assert.Len(t, reap, 1)
	assert.Equal(t, orphanID, reap[0].VolumeID)
}

// TestVolumesToReapSkipsReplicated pins the defence-in-depth check: even if
// a resolver ever reconstructs IsReplicated=true for a candidate with no
// published VolumeStatus, it must still not be reaped. getVolumeStatusByPVC
// itself can never produce this today (a PVC name carries no such bit), but
// gcVolumes is shared with the file/dataset paths, where the same combination
// is possible.
func TestVolumesToReapSkipsReplicated(t *testing.T) {
	ctx := initStatusCtx(t)
	resolve := func(string) (*types.VolumeStatus, error) {
		return &types.VolumeStatus{
			VolumeID:     uuid.Must(uuid.NewV4()),
			IsReplicated: true,
		}, nil
	}

	reap := volumesToReap(&ctx, []string{"whatever"}, resolve)
	assert.Empty(t, reap, "a replicated volume must never be reaped")
}

// TestVolumesToReapSkipsUnresolvable confirms one bad candidate - a PVC name
// this node cannot parse - is logged and skipped rather than stopping the
// whole pass or reaping something by mistake.
func TestVolumesToReapSkipsUnresolvable(t *testing.T) {
	ctx := initStatusCtx(t)
	orphanID := uuid.Must(uuid.NewV4())
	goodName := fmt.Sprintf("%s-pvc-0", orphanID.String())

	reap := volumesToReap(&ctx,
		[]string{"not-a-valid-pvc-name", goodName}, getVolumeStatusByPVC)
	assert.Len(t, reap, 1)
	assert.Equal(t, orphanID, reap[0].VolumeID)
}

// TestGcPVCsSkipsLiveVolumes exercises gcPVCs end to end through the
// swappable getPVCList seam. Every name it returns matches a published
// VolumeStatus, so volumesToReap's result is empty and gcVolumes never
// reaches DestroyVolume - the real Kubernetes delete call, which this test
// does not want to invoke.
func TestGcPVCsSkipsLiveVolumes(t *testing.T) {
	ctx := initStatusCtx(t)
	live := types.VolumeStatus{
		VolumeID:          uuid.Must(uuid.NewV4()),
		GenerationCounter: 1,
	}
	publishVolumeStatus(&ctx, &live)

	origGetPVCList := getPVCList
	getPVCList = func(*base.LogObject) ([]string, error) {
		return []string{live.GetPVCName()}, nil
	}
	t.Cleanup(func() { getPVCList = origGetPVCList })

	assert.NotPanics(t, func() { gcPVCs(&ctx) })
	assert.NotNil(t, ctx.LookupVolumeStatus(live.Key()),
		"gcPVCs must not have touched the still-published volume")
}
