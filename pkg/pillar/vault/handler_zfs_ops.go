// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
	"golang.org/x/sys/unix"
)

// vaultSwapMarkerFile records that a vault migration holds a complete staging
// copy awaiting the rename swap. It lives on /persist rather than inside the
// vault so that it is readable with the vault datasets unmounted and their
// keys unloaded, and it names the staging dataset so that a leftover from an
// unrelated attempt is not mistaken for a copy ready to promote.
// A variable so that tests can point it at a scratch directory.
var vaultSwapMarkerFile = types.PersistStatusDir + "/vault-migration-swap"

// zfsVaultOps are the storage operations the ZFS vault handler performs while
// migrating a carried-over EVE-kvm filesystem vault to the EVE-k zvol layout
// and while recovering from an interrupted migration. Tests substitute a fake
// to exercise the failure paths, which otherwise need a real pool.
type zfsVaultOps interface {
	DatasetExist(name string) bool
	CreateVaultZvol(name, keyFile string, encrypt bool, sizeBytes uint64) error
	CreateEtcdZvol(name, keyFile string, encrypt bool) error
	RenameDataset(oldName, newName string) error
	DestroyDataset(name string) error
	UnmountDataset(name string) error
	AvailableBytes(name string) (uint64, error)
	UsedBytes(name string) (uint64, error)
	// FormatStagingZvol waits for the zvol device node and puts a vault
	// filesystem on it.
	FormatStagingZvol(name string) error
	// MountStaging mounts the staging zvol and returns the mountpoint to copy
	// the vault contents into.
	MountStaging(name string) (string, error)
	UnmountStaging(mountpoint string) error
	CopyTree(srcDir, dstDir string) error
	MountVaultZvol(name string) error
	// MarkSwapReady records that the named staging dataset holds a complete
	// copy of the vault and may be promoted; SwapMarkedDataset returns that
	// name, or an empty string when no swap is recorded.
	MarkSwapReady(stagingDataset string) error
	SwapMarkedDataset() (string, error)
	ClearSwapMarker() error
}

// realZFSVaultOps implements zfsVaultOps against the pool.
type realZFSVaultOps struct {
	log *base.LogObject
}

func (o realZFSVaultOps) DatasetExist(name string) bool {
	return zfs.DatasetExist(o.log, name)
}

func (o realZFSVaultOps) CreateVaultZvol(name, keyFile string, encrypt bool, sizeBytes uint64) error {
	return zfs.CreateVaultVolumeDataset(o.log, name, keyFile, encrypt, sizeBytes,
		"zstd", zfs.VolBlockSizeBytes)
}

func (o realZFSVaultOps) CreateEtcdZvol(name, keyFile string, encrypt bool) error {
	return CreateZvolEtcd(o.log, name, keyFile, encrypt)
}

func (o realZFSVaultOps) RenameDataset(oldName, newName string) error {
	return zfs.RenameDataset(oldName, newName)
}

func (o realZFSVaultOps) DestroyDataset(name string) error {
	return zfs.DestroyDataset(name)
}

func (o realZFSVaultOps) UnmountDataset(name string) error {
	return zfs.UnmountDataset(name)
}

func (o realZFSVaultOps) AvailableBytes(name string) (uint64, error) {
	return zfs.GetDatasetAvailableBytes(name)
}

func (o realZFSVaultOps) UsedBytes(name string) (uint64, error) {
	return zfs.GetDatasetUsedBytes(name)
}

func (o realZFSVaultOps) FormatStagingZvol(name string) error {
	devPath := zfs.GetZvolPath(name)
	if err := waitPath(o.log, devPath, vaultZvolPathWaitSeconds); err != nil {
		return fmt.Errorf("zvol dev path %s missing: %v", devPath, err)
	}
	return formatZvol(o.log, devPath, vaultFsType)
}

func (o realZFSVaultOps) MountStaging(name string) (string, error) {
	if err := os.MkdirAll(vaultMigrateMountpoint, 0755); err != nil {
		return "", fmt.Errorf("cannot create migration mountpoint %s: %v",
			vaultMigrateMountpoint, err)
	}
	devPath := zfs.GetZvolPath(name)
	if err := unix.Mount(devPath, vaultMigrateMountpoint, vaultFsType,
		vaultMountFlags(), ""); err != nil {
		return "", fmt.Errorf("mount of %s at %s: %v", devPath, vaultMigrateMountpoint, err)
	}
	return vaultMigrateMountpoint, nil
}

func (o realZFSVaultOps) UnmountStaging(mountpoint string) error {
	return unix.Unmount(mountpoint, 0)
}

// CopyTree copies the contents of srcDir into the existing directory dstDir.
// fileutils.CopyDir cannot be used here because it requires the destination
// not to exist and silently drops symlinks; cp -a preserves symlinks,
// permissions and xattrs, which the containerd content store and metadata DB
// depend on.
func (o realZFSVaultOps) CopyTree(srcDir, dstDir string) error {
	out, err := base.Exec(o.log, "/bin/cp", "-a", srcDir+"/.", dstDir+"/").
		WithContext(context.Background()).
		WithUnlimitedTimeout(3600 * time.Second).CombinedOutput()
	if err != nil {
		return fmt.Errorf("copy vault contents %s -> %s: %v (%s)", srcDir, dstDir, err, out)
	}
	return nil
}

func (o realZFSVaultOps) MountVaultZvol(name string) error {
	return MountVaultZvol(o.log, name)
}

func (o realZFSVaultOps) MarkSwapReady(stagingDataset string) error {
	if err := os.MkdirAll(filepath.Dir(vaultSwapMarkerFile), 0755); err != nil {
		return err
	}
	return utils.WriteRename(vaultSwapMarkerFile, []byte(stagingDataset+"\n"))
}

func (o realZFSVaultOps) SwapMarkedDataset() (string, error) {
	contents, err := os.ReadFile(vaultSwapMarkerFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(contents)), nil
}

func (o realZFSVaultOps) ClearSwapMarker() error {
	if err := os.Remove(vaultSwapMarkerFile); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return utils.DirSync(filepath.Dir(vaultSwapMarkerFile))
}
