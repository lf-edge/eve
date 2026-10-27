// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handle publishing the existing-at-boot VolumeStatus
// Published under "unknown" objType with refcount=0. Moved to
// other objType when there is a reference.

package volumemgr

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/volumehandlers"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
	uuid "github.com/satori/go.uuid"
)

// populateExistingVolumesFormatObjects iterates over the directory and takes format
// from the name of the volume and prepares map of it
func populateExistingVolumesFormatObjects(_ *volumemgrContext, dirName string) {

	log.Functionf("populateExistingVolumesFormatObjects(%s)", dirName)
	locations, err := os.ReadDir(dirName)
	if err != nil {
		log.Errorf("populateExistingVolumesFormatObjects: read directory '%s' failed: %v",
			dirName, err)
		return
	}
	for _, location := range locations {
		tempStatus, err := getVolumeStatusByLocation(filepath.Join(dirName, location.Name()))
		if err != nil {
			log.Error(err)
			continue
		}
		log.Noticef("populateExistingVolumesFormatObjects: saving format %s for volume %s", tempStatus.ContentFormat, tempStatus.Key())
		volumeFormat[tempStatus.Key()] = tempStatus.ContentFormat
	}
	log.Functionf("populateExistingVolumesFormatObjects(%s) Done", dirName)
}

// populateExistingVolumesFormatDatasets iterates over the dataset and takes format
// from the name of the volume and prepares map of it
func populateExistingVolumesFormatDatasets(_ *volumemgrContext, dataset string) {

	log.Functionf("populateExistingVolumesFormatDatasets(%s)", dataset)
	locations, err := zfs.GetVolumesFromDataset(dataset)
	if err != nil {
		log.Errorf("populateExistingVolumesFormatDatasets: GetVolumesFromDataset '%s' failed: %v",
			dataset, err)
		return
	}
	for _, location := range locations {
		tempStatus, err := getVolumeStatusByLocation(location)
		if err != nil {
			log.Error(err)
			continue
		}
		volumeFormat[tempStatus.Key()] = tempStatus.ContentFormat
	}
	log.Functionf("populateExistingVolumesFormatDatasets(%s) Done", dataset)
}

// populateExistingVolumesFormatPVC iterates over the namespace and takes format
// from the name of the volume/PVC and prepares map of it
func populateExistingVolumesFormatPVC(_ *volumemgrContext) {

	log.Functionf("populateExistingVolumesFormatPVC")
	pvlist, err := kubeapi.GetPVCList(log, kubeapi.KubeAPITimeout())
	if err != nil {
		log.Errorf("populateExistingVolumesFormatPVC: GetPVCList failed: %v", err)
		return
	}
	for _, pvcName := range pvlist {
		tempStatus, err := getVolumeStatusByPVC(pvcName)
		if err != nil {
			log.Error(err)
			continue
		}
		volumeFormat[tempStatus.Key()] = tempStatus.ContentFormat
	}
	log.Functionf("populateExistingVolumesFormatPVC Done")

}

// Periodic garbage collection looking at RefCount=0 files in the unknown
// Others have their delete handler.
func gcObjects(ctx *volumemgrContext, dirName string) {
	log.Tracef("gcObjects(%s)", dirName)
	locationsFileInfo, err := os.ReadDir(dirName)
	if err != nil {
		log.Errorf("gcObjects: read directory '%s' failed: %v",
			dirName, err)
		return
	}
	var locations []string
	for _, location := range locationsFileInfo {
		// Skip entries belonging to other subsystems (e.g. Longhorn's
		// longhorn-disk.cfg and replicas/) to avoid spurious
		// "found unknown format volume" errors from getVolumeStatusByLocation.
		if _, skip := kubeapi.VolumeDirInternalEntriesMap()[location.Name()]; skip {
			continue
		}
		locations = append(locations, filepath.Join(dirName, location.Name()))
	}
	gcVolumes(ctx, locations)
	log.Tracef("gcObjects(%s) Done", dirName)
}

// Periodic garbage collection of children datasets in provided zfs dataset
func gcDatasets(ctx *volumemgrContext, dataset string) {
	log.Tracef("gcDatasets(%s)", dataset)
	locations, err := zfs.GetVolumesFromDataset(dataset)
	if err != nil {
		log.Errorf("gcDatasets: GetVolumesFromDataset '%s' failed: %v",
			dataset, err)
		return
	}
	gcVolumes(ctx, locations)
	log.Tracef("gcDatasets(%s) Done", dataset)
}

// getPVCList and destroyPVC are package-level vars, so a test can supply a
// fixed PVC list and see what gcPVCs deletes without a Kubernetes API server.
var getPVCList = kubeapi.GetPVCList

// gcPVCListTimeout is short because gcPVCs runs on the main loop, and a
// missed pass is retried on the next GC tick. See backupDNIDAPITimeout.
const gcPVCListTimeout = 5 * time.Second

var destroyPVC = func(ctx *volumemgrContext, vs *types.VolumeStatus) error {
	_, err := volumehandlers.GetVolumeHandler(log, ctx, vs).DestroyVolume()
	return err
}

// gcPVCs deletes the PVCs of volume generations this node has superseded.
// kubevirt.go's sweepStaleGenerations deletes a stale generation's VMIRS and
// pod but not its PVC. A purge that lands while the node is down leaves no
// VolumeStatus for the old generation, so nothing else deletes that PVC.
// Call only on EVE-k.
func gcPVCs(ctx *volumemgrContext) {
	names, err := getPVCList(log, gcPVCListTimeout)
	if err != nil {
		return // GetPVCList logs the error
	}
	for _, vs := range pvcsToReap(ctx, names) {
		log.Noticef("gcPVCs: deleting PVC %s, superseded by a newer generation of volume %s",
			vs.FileLocation, vs.VolumeID)
		if err := destroyPVC(ctx, vs); err != nil {
			log.Errorf("gcPVCs: destroyVolume '%s' failed: %v", vs.FileLocation, err)
		}
	}
}

// pvcsToReap returns the PVCs gcPVCs may delete. The PVC list is cluster-wide,
// but a controller need not send every volume to every node, so a PVC this
// node has no record of may be live elsewhere. A PVC qualifies only when:
//   - this node's config holds the same volume at a newer generation,
//   - no VolumeConfig or VolumeStatus here names the PVC's own generation,
//   - and this node owns the volume or stands in for its designated node.
func pvcsToReap(ctx *volumemgrContext, pvcNames []string) []*types.VolumeStatus {
	newest := make(map[uuid.UUID]types.VolumeConfig)
	for _, c := range ctx.subVolumeConfig.GetAll() {
		vc := c.(types.VolumeConfig)
		if cur, ok := newest[vc.VolumeID]; !ok || volumeGeneration(vc) > volumeGeneration(cur) {
			newest[vc.VolumeID] = vc
		}
	}
	var reap []*types.VolumeStatus
	for _, name := range pvcNames {
		vs, err := getVolumeStatusByPVC(name)
		if err != nil {
			log.Functionf("pvcsToReap: skipping PVC %s: %v", name, err)
			continue
		}
		vc, known := newest[vs.VolumeID]
		if !known || vs.GenerationCounter >= volumeGeneration(vc) {
			continue
		}
		if ctx.LookupVolumeStatus(vs.Key()) != nil || ctx.LookupVolumeConfig(vs.Key()) != nil {
			continue
		}
		if vc.IsReplicated && !isCurrentlyBackupDNIDForVolume(ctx, &vc) {
			continue
		}
		reap = append(reap, vs)
	}
	return reap
}

// volumeGeneration is the generation a volume's key and PVC name carry.
func volumeGeneration(vc types.VolumeConfig) int64 {
	return vc.GenerationCounter + vc.LocalGenerationCounter
}

func gcVolumes(ctx *volumemgrContext, locations []string) {
	for _, location := range locations {
		tempVolumeStatus, err := getVolumeStatusByLocation(location)
		if err != nil {
			log.Errorf("gcVolumes: getVolumeStatusByLocation '%s' failed: %v",
				location, err)
			continue
		}
		// Do not GC a replicated volume.
		if tempVolumeStatus != nil && tempVolumeStatus.IsReplicated {
			continue
		}
		vs := ctx.LookupVolumeStatus(tempVolumeStatus.Key())
		if vs == nil {
			log.Functionf("gcVolumes: Found unused volume %s. Deleting it.",
				location)
			if _, err := volumehandlers.GetVolumeHandler(log, ctx, tempVolumeStatus).DestroyVolume(); err != nil {
				log.Errorf("gcVolumes: destroyVolume '%s' failed: %v",
					location, err)
			}
		}
	}
}

func getVolumeStatusByPVC(pvcName string) (*types.VolumeStatus, error) {
	var encrypted bool
	var parsedFormat int32
	var volumeIDAndGeneration string

	volumeIDAndGeneration = pvcName
	parsedFormat = int32(zconfig.Format_PVC)

	generation := strings.Split(volumeIDAndGeneration, "-pvc-")
	volUUID, err := uuid.FromString(generation[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse VolumeID: %s", err)
	}
	if len(generation) == 1 {
		return nil, fmt.Errorf("cannot extract generation from PVC %s", pvcName)
	}
	// we cannot extract LocalGenerationCounter from the PVC name
	// assume it is zero
	generationCounter, err := strconv.ParseInt(generation[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GenerationCounter: %s", err)
	}
	vs := types.VolumeStatus{
		VolumeID:          volUUID,
		Encrypted:         encrypted,
		GenerationCounter: generationCounter,
		ContentFormat:     zconfig.Format(parsedFormat),
		FileLocation:      pvcName,
	}
	return &vs, nil
}

func getVolumeStatusByLocation(location string) (*types.VolumeStatus, error) {
	var encrypted bool
	var parsedFormat int32
	var volumeIDAndGeneration string

	// assume it is zvol
	if strings.HasPrefix(location, types.VolumeEncryptedZFSDataset) || strings.HasPrefix(location, types.VolumeClearZFSDataset) {
		encrypted = strings.HasPrefix(location, types.VolumeEncryptedZFSDataset)
		volumeIDAndGeneration = filepath.Base(location)
		parsedFormat = int32(zconfig.Format_RAW)
	} else {
		encrypted = strings.HasPrefix(location, types.SealedDirName)
		keyAndFormat := strings.Split(filepath.Base(location), ".")
		if len(keyAndFormat) != 2 {
			return nil, fmt.Errorf("found unknown format volume %s", location)
		}
		volumeIDAndGeneration = keyAndFormat[0]
		ok := false
		log.Noticef("getVolumeStatusByLocation: parsing format from location %s", location)
		log.Noticef("getVolumeStatusByLocation: found format %s", keyAndFormat[1])
		parsedFormat, ok = zconfig.Format_value[strings.ToUpper(keyAndFormat[1])]
		if !ok {
			return nil, fmt.Errorf("found unknown format volume %s", location)
		}
		log.Noticef("getVolumeStatusByLocation: the format as digit %d", parsedFormat)
		volumeIDAndGeneration = strings.ReplaceAll(volumeIDAndGeneration, "#", ".")
	}

	generation := strings.Split(volumeIDAndGeneration, ".")
	volUUID, err := uuid.FromString(generation[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse VolumeID: %s", err)
	}
	if len(generation) == 1 {
		return nil, fmt.Errorf("cannot extract generation from zVolName")
	}
	// we cannot extract LocalGenerationCounter from the zVolName
	// assume it is zero
	generationCounter, err := strconv.ParseInt(generation[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GenerationCounter: %s", err)
	}
	vs := types.VolumeStatus{
		VolumeID:          volUUID,
		Encrypted:         encrypted,
		GenerationCounter: generationCounter,
		ContentFormat:     zconfig.Format(parsedFormat),
		FileLocation:      location,
	}
	log.Noticef("getVolumeStatusByLocation: found volume %s, content format %s", location, vs.ContentFormat)
	return &vs, nil
}

// gcPendingCreateVolume remove volumes not created on previous boot
func gcPendingCreateVolume(ctx *volumemgrContext) {
	log.Trace("gcPendingCreateVolume")

	// to not repeat the logic
	unpublish := func(vcp types.VolumeCreatePending) {
		if err := ctx.pubVolumeCreatePending.Unpublish(vcp.Key()); err != nil {
			log.Errorf("gcPendingCreateVolume: cannot unpublish %s: %s", vcp.Key(), err)
		}
	}

	for _, obj := range ctx.pubVolumeCreatePending.GetAll() {
		vcp := obj.(types.VolumeCreatePending)
		var location string
		// check for zvol
		zVolDevice := zfs.GetZVolDeviceByDataset(vcp.ZVolName())
		fi, err := os.Stat(zVolDevice)
		if err == nil && fi.Mode()&os.ModeDevice != 0 {
			location = vcp.ZVolName()
		} else {
			_, err := os.Stat(vcp.PathName())
			if err != nil {
				log.Errorf("gcPendingCreateVolume: cannot get file status %s: %s", vcp.Key(), err)
				unpublish(vcp)
				continue
			}
			location = vcp.PathName()
		}
		tempVolumeStatus, err := getVolumeStatusByLocation(location)
		if err != nil {
			log.Errorf("gcPendingCreateVolume: cannot get volume status %s: %s", vcp.Key(), err)
			unpublish(vcp)
			continue
		}
		if _, err := volumehandlers.GetVolumeHandler(log, ctx, tempVolumeStatus).DestroyVolume(); err != nil {
			log.Errorf("gcPendingCreateVolume: error destroyVolume: %s", err)
			unpublish(vcp)
			continue
		}
		unpublish(vcp)
	}
	log.Trace("gcPendingCreateVolume done")
}
