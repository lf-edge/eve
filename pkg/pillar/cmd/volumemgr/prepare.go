// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lf-edge/edge-containers/pkg/registry"
	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

func getVolumeFilePath(ctx *volumemgrContext, status types.VolumeStatus) (string, error) {
	puller := registry.Puller{
		Image: status.ReferenceName,
	}
	casClient, err := cas.NewCAS(casClientType)
	if err != nil {
		err = fmt.Errorf("getVolumeFilePathAndVSize: exception while initializing CAS client: %s", err.Error())
		return "", err
	}
	defer casClient.CloseClient()
	ctrdCtx, done := casClient.CtrNewUserServicesCtx()
	defer done()

	resolver, err := casClient.Resolver(ctrdCtx)
	if err != nil {
		errStr := fmt.Sprintf("error getting CAS resolver: %v", err)
		log.Error(errStr)
		return "", errors.New(errStr)
	}
	pathToFile := ""
	_, i, err := puller.Config(true, os.Stderr, resolver)
	if err != nil {
		errStr := fmt.Sprintf("error Config for ref %s: %v", status.ReferenceName, err)
		log.Error(errStr)
		return "", errors.New(errStr)
	}
	if len(i.RootFS.DiffIDs) > 0 {
		// FIXME we expects root in the first layer for now
		b := i.RootFS.DiffIDs[0]
		// FIXME we need the proper way to extract file from content dir of containerd
		pathToFile = filepath.Join(types.ContainerdContentDir, "blobs", b.Algorithm().String(), b.Encoded())
	}

	if pathToFile == "" {
		errStr := fmt.Sprintf("no blobs to convert found for ref %s", status.ReferenceName)
		log.Error(errStr)
		return "", errors.New(errStr)
	}
	return pathToFile, nil
}

func prepareZVol(ctx *volumemgrContext, status types.VolumeStatus) error {
	size := status.MaxVolSize
	if status.ReferenceName != "" {
		pathToFile, err := getVolumeFilePath(ctx, status)
		if err != nil {
			errStr := fmt.Sprintf("Error obtaining file for zvol at volume %s, error=%v",
				status.Key(), err)
			log.Error(errStr)
			return errors.New(errStr)
		}
		size, _, err = checkResizeDisk(pathToFile, status.MaxVolSize)
		if err != nil {
			errStr := fmt.Sprintf("Error creating zfs zvol at checkResizeDisk %s, error=%v",
				pathToFile, err)
			log.Error(errStr)
			return errors.New(errStr)
		}
	}
	zVolName := status.ZVolName(types.VolumeZFSPool)
	if stdoutStderr, err := zfs.CreateVolumeDataset(log, zVolName, size, "on"); err != nil {
		errStr := fmt.Sprintf("Error creating zfs zvol at %s, error=%v, output=%s",
			zVolName, err, stdoutStderr)
		log.Error(errStr)
		return errors.New(errStr)
	}
	return nil
}

func prepareVolume(ctx *volumemgrContext, status types.VolumeStatus) error {
	log.Tracef("prepareVolume: %s", status.Key())
	if ctx.persistType != types.PersistZFS || status.IsContainer() {
		return nil
	}
	return prepareZVol(ctx, status)
}
