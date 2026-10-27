// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
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
	// A PVC name carries only the sum of the two counters, so the parse puts
	// it all in GenerationCounter. GetPVCName must round-trip against that.
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

// pvcGCFixture is a volumemgr context whose VolumeConfig subscription is
// backed by a memory driver, so pvcsToReap sees the configs a test publishes.
type pvcGCFixture struct {
	t   *testing.T
	ctx *volumemgrContext
	pub pubsub.Publication
}

func newPVCGCFixture(t *testing.T) *pvcGCFixture {
	ctx, pub := initVolumeModifyCtxForTest(t)
	return &pvcGCFixture{t: t, ctx: ctx, pub: pub}
}

func (f *pvcGCFixture) config(vc types.VolumeConfig) {
	publishTestVolumeConfig(f.t, f.ctx, f.pub, vc)
}

func (f *pvcGCFixture) status(vs types.VolumeStatus) {
	publishVolumeStatus(f.ctx, &vs)
}

func (f *pvcGCFixture) reaped(names ...string) []string {
	var out []string
	for _, vs := range pvcsToReap(f.ctx, names) {
		out = append(out, vs.FileLocation)
	}
	return out
}

func pvcName(id uuid.UUID, generation int64) string {
	return fmt.Sprintf("%s-pvc-%d", id, generation)
}

// The orphan gcPVCs exists for: this node owns the volume at generation 1,
// and the generation 0 PVC has no VolumeStatus left to delete it.
func TestPVCsToReapSupersededGeneration(t *testing.T) {
	f := newPVCGCFixture(t)
	id := uuid.Must(uuid.NewV4())
	f.config(types.VolumeConfig{VolumeID: id, GenerationCounter: 1})

	assert.Equal(t, []string{pvcName(id, 0)}, f.reaped(pvcName(id, 0), pvcName(id, 1)))
}

// A local purge raises LocalGenerationCounter, not GenerationCounter. The
// PVC name carries the sum, so generation 2+3 supersedes PVC 4 and keeps 5.
func TestPVCsToReapUsesSummedGeneration(t *testing.T) {
	f := newPVCGCFixture(t)
	id := uuid.Must(uuid.NewV4())
	live := types.VolumeConfig{VolumeID: id, GenerationCounter: 2, LocalGenerationCounter: 3}
	f.config(live)
	f.status(types.VolumeStatus{VolumeID: id, GenerationCounter: 2, LocalGenerationCounter: 3})

	assert.Equal(t, []string{pvcName(id, 4)}, f.reaped(pvcName(id, 4), live.GetPVCName()))
}

// A controller may send a volume to some cluster nodes only. A node without
// it still lists the cluster-wide PVC, and must leave it alone.
func TestPVCsToReapKeepsVolumeUnknownToThisNode(t *testing.T) {
	f := newPVCGCFixture(t)
	assert.Empty(t, f.reaped(pvcName(uuid.Must(uuid.NewV4()), 0)))
}

// A standalone volume no app refers to is still in the config, so its PVC
// stays. This holds before volumemgr creates its VolumeStatus too, while
// the create is deferred until zedagent finishes parsing the config.
func TestPVCsToReapKeepsStandaloneVolume(t *testing.T) {
	f := newPVCGCFixture(t)
	id := uuid.Must(uuid.NewV4())
	f.config(types.VolumeConfig{VolumeID: id, HasNoAppReferences: true})

	assert.Empty(t, f.reaped(pvcName(id, 0)))
}

// Mid-purge, both generations can be in the config at once. The older one
// is still named by a VolumeConfig, so it is not an orphan yet.
func TestPVCsToReapKeepsGenerationStillConfigured(t *testing.T) {
	f := newPVCGCFixture(t)
	id := uuid.Must(uuid.NewV4())
	f.config(types.VolumeConfig{VolumeID: id, GenerationCounter: 0})
	f.config(types.VolumeConfig{VolumeID: id, GenerationCounter: 1})

	assert.Empty(t, f.reaped(pvcName(id, 0)))
}

// The normal delete path is still running for the old generation.
func TestPVCsToReapKeepsGenerationWithStatus(t *testing.T) {
	f := newPVCGCFixture(t)
	id := uuid.Must(uuid.NewV4())
	f.config(types.VolumeConfig{VolumeID: id, GenerationCounter: 1})
	f.status(types.VolumeStatus{VolumeID: id, GenerationCounter: 0,
		SubState: types.VolumeSubStateDeleting})

	assert.Empty(t, f.reaped(pvcName(id, 0)))
}

func TestPVCsToReapKeepsNewerGeneration(t *testing.T) {
	f := newPVCGCFixture(t)
	id := uuid.Must(uuid.NewV4())
	f.config(types.VolumeConfig{VolumeID: id, GenerationCounter: 1})

	assert.Empty(t, f.reaped(pvcName(id, 2)))
}

func TestPVCsToReapSkipsForeignPVCs(t *testing.T) {
	f := newPVCGCFixture(t)
	assert.Empty(t, f.reaped("data-postgres-0", "not-a-uuid-pvc-1"))
}

// A node that holds only a replica of the volume leaves the delete to the
// designated node.
func TestPVCsToReapReplicaLeavesItToDesignatedNode(t *testing.T) {
	f := newPVCGCFixture(t)
	id := uuid.Must(uuid.NewV4())
	f.config(types.VolumeConfig{VolumeID: id, GenerationCounter: 1,
		IsReplicated: true, DesignatedNodeUUID: uuid.Must(uuid.NewV4()).String()})

	assert.Empty(t, f.reaped(pvcName(id, 0)))
}

// While the designated node is down, the backup DNID deletes the orphan in
// its place.
func TestPVCsToReapBackupDNIDStandsIn(t *testing.T) {
	f := newPVCGCFixture(t)
	f.ctx.hvTypeKube = true
	f.ctx.isAppOpLeader = true
	f.ctx.isCurrentlyBackupDNIDFunc = func(*base.LogObject, kubeapi.NodeHealthLookup,
		string, bool, types.Affinity, time.Duration) bool {
		return true
	}
	id := uuid.Must(uuid.NewV4())
	f.config(types.VolumeConfig{VolumeID: id, GenerationCounter: 1,
		IsReplicated: true, DesignatedNodeUUID: uuid.Must(uuid.NewV4()).String()})

	assert.Equal(t, []string{pvcName(id, 0)}, f.reaped(pvcName(id, 0)))
}

// stubPVCGC replaces the PVC list and the destroy, and returns the PVCs
// gcPVCs destroys.
func stubPVCGC(t *testing.T, names []string, listErr error) *[]string {
	origGetPVCList, origDestroyPVC := getPVCList, destroyPVC
	t.Cleanup(func() { getPVCList, destroyPVC = origGetPVCList, origDestroyPVC })
	getPVCList = func(*base.LogObject, time.Duration) ([]string, error) { return names, listErr }
	destroyed := &[]string{}
	destroyPVC = func(_ *volumemgrContext, vs *types.VolumeStatus) error {
		*destroyed = append(*destroyed, vs.FileLocation)
		return nil
	}
	return destroyed
}

// gcPVCs destroys the superseded PVC, and leaves the live one and a PVC for a
// volume this node does not know.
func TestGcPVCsDestroysOnlyOrphans(t *testing.T) {
	f := newPVCGCFixture(t)
	id := uuid.Must(uuid.NewV4())
	f.config(types.VolumeConfig{VolumeID: id, GenerationCounter: 1})
	f.status(types.VolumeStatus{VolumeID: id, GenerationCounter: 1})
	destroyed := stubPVCGC(t, []string{pvcName(id, 0), pvcName(id, 1),
		pvcName(uuid.Must(uuid.NewV4()), 0)}, nil)

	gcPVCs(f.ctx)
	assert.Equal(t, []string{pvcName(id, 0)}, *destroyed)
}

func TestGcPVCsListErrorDestroysNothing(t *testing.T) {
	f := newPVCGCFixture(t)
	id := uuid.Must(uuid.NewV4())
	f.config(types.VolumeConfig{VolumeID: id, GenerationCounter: 1})
	destroyed := stubPVCGC(t, []string{pvcName(id, 0)}, fmt.Errorf("API down"))

	gcPVCs(f.ctx)
	assert.Empty(t, *destroyed)
}
