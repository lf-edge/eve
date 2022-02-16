// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	snapshotsapi "github.com/containerd/containerd/api/services/snapshots/v1"
	"github.com/containerd/containerd/contrib/snapshotservice"
	"github.com/containerd/containerd/snapshots"
	overlaySnapshooter "github.com/containerd/containerd/snapshots/overlay"
	zfsSnapshooter "github.com/containerd/zfs"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// EveSnapshotterInit initializes custom containerd snapshotter
// we use proxy plugin and start it here after defaultVault is mounted
func EveSnapshotterInit(snapshotter types.EveSnapshotter) error {
	dirToSaveMetadata := filepath.Join(types.PersistDir, "vault", snapshotter.String())
	err := os.MkdirAll(dirToSaveMetadata, os.ModeDir)
	if err != nil {
		return err
	}
	var sn snapshots.Snapshotter
	switch snapshotter {
	case types.ZFSSnapshotter:
		//it makes lookup internally for mount point of provided path
		sn, err = zfsSnapshooter.NewSnapshotter(dirToSaveMetadata)
		if err != nil {
			return err
		}
	case types.OverlaySnapshotter:
		sn, err = overlaySnapshooter.NewSnapshotter(dirToSaveMetadata)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("no custom snapshotter for %s", snapshotter.String())
	}
	service := snapshotservice.FromSnapshotter(sn)
	rpc := grpc.NewServer()
	snapshotsapi.RegisterSnapshotsServer(rpc, service)

	// socket must be in sync with containerd config.toml
	l, err := net.Listen("unix", fmt.Sprintf("/run/%s.sock", snapshotter))
	if err != nil {
		return err
	}
	go func() {
		if err := rpc.Serve(l); err != nil {
			logrus.Fatalf("EveSnapshotterInit %s Serve error: %v\n", snapshotter, err)
		}
	}()
	return nil
}
