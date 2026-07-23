// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	libzfs "github.com/andrewd-zededa/go-libzfs"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
	"golang.org/x/sys/unix"
)

const (
	zfsKeyDir                       = "/run/TmpVaultDir2"
	zfsKeyFile                      = zfsKeyDir + "/protector.key"
	vaultZvolPathWaitSeconds int64  = 20
	vaultFsType              string = "ext4"

	// cmdlineNoDirsync is the kernel cmdline flag to disable DIRSYNC for the vault mount.
	// DIRSYNC improves filesystem content consistency on power outage but introduces
	// significant I/O overhead in virtualized environments.
	// Set this flag when EVE runs as a VM.
	// Must be kept in sync with the grub function set_no_dirsync in pkg/grub/rootfs.cfg.
	cmdlineNoDirsync = "eve_no_dirsync"
)

// ZFSHandler handles vault operations with ZFS
type ZFSHandler struct {
	log     *base.LogObject
	options HandlerOptions
}

// GetOperationalInfo returns status of encryption and string with information
func (h *ZFSHandler) GetOperationalInfo() (info.DataSecAtRestStatus, string) {
	if !etpm.IsTpmEnabled() {
		// No encryption on platforms without a (working) TPM
		h.log.Trace("Setting status to disabled, TPM is not in use")
		return info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED,
			"TPM is either absent or not in use"
	}
	// Check if default zpool (i.e. "persist" dataset) is setup
	if !zfs.DatasetExist(h.log, types.PersistDataset) {
		h.log.Errorf("default ZFS zpool is not setup")
		return info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR,
			"Default ZFS zpool is not setup"
	}
	return info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED,
		"ZFS Encryption is enabled for vaults"
}

// SetupDeprecatedVaults is dummy for ZFSHandler
func (h *ZFSHandler) SetupDeprecatedVaults() error {
	return nil
}

// SetHandlerOptions adjust handler options
func (h *ZFSHandler) SetHandlerOptions(options HandlerOptions) {
	h.options = options
}

// GetVaultStatuses returns statuses of vault(s)
func (h *ZFSHandler) GetVaultStatuses() []*types.VaultStatus {
	return []*types.VaultStatus{h.getVaultStatus(types.DefaultVaultName, types.SealedDataset)}
}

// UnlockDefaultVault e.g. zfs load-key persist/vault followed by
// zfs mount persist/vault
func (h *ZFSHandler) UnlockDefaultVault() error {
	return h.unlockVault(types.SealedDataset)
}

// RemoveDefaultVault removes vault from zfs
// e.g. zfs destroy -fr persist/vault
func (h *ZFSHandler) RemoveDefaultVault() error {
	if err := zfs.UnmountDataset(types.SealedDataset); err != nil {
		h.log.Errorf("Error unmounting vault %s, error=%v", types.SealedDataset, err)
		return err
	}

	if err := zfs.DestroyDataset(types.SealedDataset); err != nil {
		h.log.Errorf("Error destroying vault %s, error=%v", types.SealedDataset, err)
		return err
	}

	return nil
}

// SetupDefaultVault setups vaults on zfs, using zfs native encryption support
func (h *ZFSHandler) SetupDefaultVault() error {
	if !etpm.IsTpmEnabled() {
		if base.IsHVTypeKube() {
			if zfs.DatasetExist(h.log, types.SealedDataset) {
				// A device converted from EVE-kvm carries a filesystem-dataset
				// vault here, not the native EVE-k zvol+etcd layout. Migrate it
				// so a converted no-TPM device ends up with the same layout a
				// fresh EVE-k install has, including the etcd-storage zvol. Once
				// migrated the vault is a zvol and we just mount it. (Field
				// devices take the TPM path in unlockVault instead.)
				isZvol, err := zfs.IsDatasetTypeZvol(types.SealedDataset)
				if err != nil {
					return fmt.Errorf("error checking vault dataset type for %s: %v",
						types.SealedDataset, err)
				}
				if vaultNeedsZvolMigration(true, isZvol) {
					// Mount the carried-over fs vault as the copy source, then
					// migrate to the zvol layout unencrypted: no-TPM ZFS vaults
					// carry no key.
					if mounted, merr := zfs.IsDatasetMounted(types.SealedDataset); merr != nil {
						return merr
					} else if !mounted {
						if err := zfs.MountDataset(types.SealedDataset); err != nil {
							return err
						}
					}
					return h.migrateVaultFsToZvol(types.SealedDataset, "", false)
				}
				return h.mountVaultByDatasetType(types.SealedDataset)
			}
			if err := CreateZvolEtcd(h.log, types.EtcdZvol, "", false); err != nil {
				return fmt.Errorf("error creating zfs etcd zvol %s, error=%v",
					types.EtcdZvol, err)
			}
			if err := CreateZvolVault(h.log, types.SealedDataset, "", false); err != nil {
				return fmt.Errorf("error creating zfs non-tpm vault %s, error=%v",
					types.SealedDataset, err)
			}
			return nil
		}
		if zfs.DatasetExist(h.log, types.SealedDataset) {
			return nil
		}
		if err := zfs.CreateDataset(types.SealedDataset); err != nil {
			return fmt.Errorf("error creating zfs vault %s, error=%v",
				types.SealedDataset, err)
		}
		return nil
	}

	if err := h.setupVault(types.SealedDataset); err != nil {
		return fmt.Errorf("error in setting up ZFS vault %s:%v", types.SealedDataset, err)
	}
	// Log the type of key used for unlocking default vault
	h.log.Noticef("default zfs vault unlocked using key type: %s",
		etpm.CompareLegacyandSealedKey(h.log).String())
	return nil
}

func (h *ZFSHandler) unlockVault(vaultPath string) error {
	// prepare key in the staging file
	// we never unlock a deprecated vault in ZFS (we never created those)
	// cloudKeyOnlyMode=false, useSealedKey=true
	unstage, err := stageKey(h.log, false, true, h.options.TpmKeyOnlyMode, zfsKeyDir, zfsKeyFile)
	if err != nil {
		return err
	}
	defer unstage()

	// zfs load-key
	args := []string{"load-key", vaultPath}
	if stdOut, stdErr, err := execCmd(types.ZFSBinary, args...); err != nil {
		h.log.Errorf("Error loading key for vault: %v, %s, %s",
			err, stdOut, stdErr)
		return err
	}

	// zfs mount
	if base.IsHVTypeKube() {
		isZvol, err := zfs.IsDatasetTypeZvol(vaultPath)
		if err != nil {
			h.log.Errorf("Error checking vault dataset type for %s: %v", vaultPath, err)
			return err
		}
		if vaultNeedsZvolMigration(true, isZvol) {
			// Carried-over kvm filesystem vault on an EVE-k device (the device
			// was converted from EVE-kvm). Mount it as a filesystem so the
			// device boots, then migrate it in place to the zvol layout EVE-k
			// expects. The unlock key is still staged for the encrypted creates.
			h.log.Noticef("Detected carried-over kvm filesystem vault %s on EVE-k; migrating to zvol layout",
				vaultPath)
			if mounted, merr := zfs.IsDatasetMounted(vaultPath); merr != nil {
				h.log.Errorf("Error checking mount state of %s: %v", vaultPath, merr)
				return merr
			} else if !mounted {
				if err := zfs.MountDataset(vaultPath); err != nil {
					h.log.Errorf("Error mounting carried-over fs vault %s: %v", vaultPath, err)
					return err
				}
			}
			return h.migrateVaultFsToZvol(vaultPath, zfsKeyFile, true)
		}
		// Native EVE-k zvol vault.
		// zfs load-key here separately for types.EtcdZvol because we don't mount it here, only in kube.
		args := []string{"load-key", types.EtcdZvol}
		if stdOut, stdErr, err := execCmd(types.ZFSBinary, args...); err != nil {
			h.log.Errorf("Error loading key for etcd vol vault: %v, %s, %s",
				err, stdOut, stdErr)
			return err
		}
		if err := MountVaultZvol(h.log, vaultPath); err != nil {
			h.log.Errorf("Error unlocking vault: %v", err)
			return err
		}
	} else {
		if err := zfs.MountDataset(vaultPath); err != nil {
			h.log.Errorf("Error unlocking vault: %v", err)
			return err
		}
	}

	return nil
}

// vaultNeedsZvolMigration reports whether a just-unlocked ZFS vault must be
// migrated from the EVE-kvm filesystem-dataset layout to the EVE-k zvol
// layout. It is true only on EVE-k when the existing vault is a filesystem
// dataset (i.e. carried over from a kvm install during a cross-flavor update).
func vaultNeedsZvolMigration(isKube bool, vaultIsZvol bool) bool {
	return isKube && !vaultIsZvol
}

// mountVaultByDatasetType mounts vaultPath according to its actual ZFS dataset
// type: as a zvol-backed ext4 filesystem if it is a zvol (the native EVE-k
// layout), otherwise as a ZFS filesystem dataset (a carried-over EVE-kvm vault
// not yet migrated to the zvol layout). It assumes any required key is already
// loaded. Used where the type is not known up front (the no-TPM
// SetupDefaultVault path); unlockVault drives the type-aware migration itself.
func (h *ZFSHandler) mountVaultByDatasetType(vaultPath string) error {
	isZvol, err := zfs.IsDatasetTypeZvol(vaultPath)
	if err != nil {
		h.log.Errorf("mountVaultByDatasetType: IsDatasetTypeZvol(%s) failed: %v; assuming filesystem",
			vaultPath, err)
	}
	if isZvol {
		return MountVaultZvol(h.log, vaultPath)
	}
	h.log.Noticef("mountVaultByDatasetType: %s is a filesystem dataset (carried-over EVE-kvm vault); mounting as filesystem",
		vaultPath)
	return zfs.MountDataset(vaultPath)
}

// vaultMigrateMountpoint is the temporary mountpoint used while copying the
// carried-over filesystem vault into the new zvol-backed ext4 during migration.
const vaultMigrateMountpoint = "/run/vaultmgr/vault-migrate"

// migrateVaultFsToZvol migrates a carried-over EVE-kvm filesystem vault to the
// EVE-k zvol+ext4 layout, preserving the vault contents (containerd content
// store and metadata, downloader, verifier, configs). It must be called with
// the source filesystem vault mounted at /<vaultPath>. When encrypt is true the
// new zvols are created encrypted, which requires the vault unlock key already
// staged (the TPM path via unlockVault); when false they are created
// unencrypted (the no-TPM path via SetupDefaultVault).
//
// The sequence stages a new zvol "<vaultPath>2", copies the vault contents into
// it, then destroys the old filesystem vault and renames the new one into
// place. It is re-entrant: a leftover staging zvol from an interrupted attempt
// is removed first, and once the rename has happened the vault is a zvol and
// the caller takes the native path instead of calling this.
func (h *ZFSHandler) migrateVaultFsToZvol(vaultPath, keyFile string, encrypt bool) error {
	stagingDataset := vaultPath + "2"

	// Re-entrancy: drop any staging zvol left behind by an interrupted attempt.
	if zfs.DatasetExist(h.log, stagingDataset) {
		h.log.Warnf("Removing stale migration zvol %s from a previous attempt", stagingDataset)
		_ = unix.Unmount(vaultMigrateMountpoint, 0)
		_ = zfs.UnmountDataset(stagingDataset)
		if err := zfs.DestroyDataset(stagingDataset); err != nil {
			return fmt.Errorf("cannot remove stale migration zvol %s: %v", stagingDataset, err)
		}
	}

	// Empty etcd zvol: etcd/k3s start fresh on EVE-k, there is nothing to carry
	// over. Skip if a prior attempt already created it.
	if !zfs.DatasetExist(h.log, types.EtcdZvol) {
		if err := CreateZvolEtcd(h.log, types.EtcdZvol, keyFile, encrypt); err != nil {
			return fmt.Errorf("error creating etcd zvol %s: %v", types.EtcdZvol, err)
		}
	}

	// Size the staging zvol to the currently-free pool space (the source vault
	// is still present). Reusing CreateVaultVolumeDataset gives the staging zvol
	// the same treatment a fresh-install EVE-k vault gets, just sized to free
	// space rather than the whole pool; peak usage is then ~the vault contents.
	availBytes, err := zfs.GetDatasetAvailableBytes(types.PersistDataset)
	if err != nil {
		return fmt.Errorf("cannot read %s available bytes: %v", types.PersistDataset, err)
	}
	if availBytes <= zfs.VolBlockSizeBytes {
		return fmt.Errorf("insufficient free space (%d bytes) to migrate vault %s",
			availBytes, vaultPath)
	}
	sizeBytes := availBytes - zfs.VolBlockSizeBytes
	if err := zfs.CreateVaultVolumeDataset(h.log, stagingDataset, keyFile, encrypt,
		sizeBytes, "zstd", zfs.VolBlockSizeBytes); err != nil {
		return fmt.Errorf("error creating migration zvol %s: %v", stagingDataset, err)
	}

	devPath := zfs.GetZvolPath(stagingDataset)
	if err := waitPath(h.log, devPath, vaultZvolPathWaitSeconds); err != nil {
		return fmt.Errorf("migration zvol dev path missing: %v", err)
	}
	if err := formatZvol(h.log, devPath, vaultFsType); err != nil {
		return fmt.Errorf("migration zvol format error: %v", err)
	}

	if err := os.MkdirAll(vaultMigrateMountpoint, 0755); err != nil {
		return fmt.Errorf("cannot create migration mountpoint %s: %v", vaultMigrateMountpoint, err)
	}
	mountFlags := uintptr(unix.MS_DIRSYNC | unix.MS_NOATIME)
	if noDirsyncRequested() {
		mountFlags = unix.MS_NOATIME
	}
	if err := unix.Mount(devPath, vaultMigrateMountpoint, vaultFsType, mountFlags, ""); err != nil {
		return fmt.Errorf("mount of migration zvol %s at %s: %v", devPath, vaultMigrateMountpoint, err)
	}

	// Copy the carried-over vault contents into the new zvol-backed ext4. The
	// destination is the already-mounted zvol; fileutils.CopyDir cannot be used
	// here because it requires the destination not to exist and silently drops
	// symlinks. cp -a copies into the existing mountpoint and preserves
	// symlinks, permissions, and xattrs, which the containerd content store and
	// metadata DB depend on.
	srcDir := "/" + vaultPath
	ctx := context.Background()
	if out, err := base.Exec(h.log, "/bin/cp", "-a", srcDir+"/.", vaultMigrateMountpoint+"/").
		WithContext(ctx).WithUnlimitedTimeout(3600 * time.Second).CombinedOutput(); err != nil {
		_ = unix.Unmount(vaultMigrateMountpoint, 0)
		return fmt.Errorf("copy vault contents %s -> %s: %v (%s)", srcDir, vaultMigrateMountpoint, err, out)
	}

	// Swap: unmount both, destroy the old filesystem vault, rename the staging
	// zvol into place. The destroy+rename is the only non-idempotent window; the
	// re-entry guard above reconstructs from the staging zvol if interrupted
	// before the rename completes.
	if err := unix.Unmount(vaultMigrateMountpoint, 0); err != nil {
		return fmt.Errorf("unmount migration zvol at %s: %v", vaultMigrateMountpoint, err)
	}
	if err := zfs.UnmountDataset(vaultPath); err != nil {
		return fmt.Errorf("unmount old fs vault %s: %v", vaultPath, err)
	}
	if err := zfs.DestroyDataset(vaultPath); err != nil {
		return fmt.Errorf("destroy old fs vault %s: %v", vaultPath, err)
	}
	if err := zfs.RenameDataset(stagingDataset, vaultPath); err != nil {
		return fmt.Errorf("rename %s -> %s: %v", stagingDataset, vaultPath, err)
	}

	// Mount the migrated zvol vault at /<vaultPath> for the rest of this boot.
	if err := MountVaultZvol(h.log, vaultPath); err != nil {
		return fmt.Errorf("mount migrated zvol vault %s: %v", vaultPath, err)
	}

	h.log.Noticef("Migrated ZFS vault %s from kvm filesystem layout to EVE-k zvol layout", vaultPath)
	return nil
}

// e.g. zfs create -o encryption=aes-256-gcm -o keylocation=file://tmp/raw.key -o keyformat=raw persist/vault
func (h *ZFSHandler) createVault(vaultPath string) error {
	// prepare key in the staging file
	// we never create deprecated vault on ZFS
	// cloudKeyOnlyMode=false, useSealedKey=true
	unstage, err := stageKey(h.log, false, true, h.options.TpmKeyOnlyMode, zfsKeyDir, zfsKeyFile)
	if err != nil {
		return err
	}
	defer unstage()

	if base.IsHVTypeKube() {
		if err := CreateZvolEtcd(h.log, types.EtcdZvol, zfsKeyFile, true); err != nil {
			return fmt.Errorf("error creating zfs etcd zvol %s, error=%v", types.EtcdZvol, err)
		}
		if err := CreateZvolVault(h.log, vaultPath, zfsKeyFile, true); err != nil {
			h.log.Errorf("Error creating zfs vault %s, error=%v", vaultPath, err)
			return err
		}
	} else {
		if err := zfs.CreateVaultDataset(vaultPath, zfsKeyFile); err != nil {
			h.log.Errorf("Error creating zfs vault %s, error=%v", vaultPath, err)
			return err
		}
	}

	h.log.Functionf("Created new vault %s", vaultPath)
	return nil
}

// e.g. zfs get keystatus persist/vault
func (h *ZFSHandler) checkZfsKeyStatus(vaultPath string) error {
	if _, err := zfs.GetDatasetKeyStatus(vaultPath); err != nil {
		h.log.Tracef("keystatus query for %s results in error=%v",
			vaultPath, err)
		return err
	}

	return nil
}

func (h *ZFSHandler) setupVault(vaultPath string) error {
	// zfs get keystatus returns success as long as vaultPath is a dataset,
	// (even if not mounted yet), so use it to check dataset presence
	if err := h.checkZfsKeyStatus(vaultPath); err == nil {
		//present, call unlock
		return h.unlockVault(vaultPath)
	}
	// If it does not exist then the mount presumbly does not exist either but
	// double check.
	if !isDirEmpty(h.log, vaultPath) {
		h.log.Noticef("Not disturbing non-empty vault(%s)",
			vaultPath)
	} else {
		h.log.Warnf("Clear saved keys for empty vault(%s)",
			vaultPath)
		if err := etpm.WipeOutStaleSealedKeyIfAny(); err != nil {
			h.log.Errorf("WipeOutStaleSealKeyIfAny failed: %s", err)
		}
	}
	// try creating the dataset
	return h.createVault(vaultPath)
}

func (h *ZFSHandler) getVaultStatus(vaultName, vaultPath string) *types.VaultStatus {
	status := types.VaultStatus{}
	status.Name = vaultName

	if etpm.PCRBankSHA256Enabled() {
		status.PCRStatus = info.PCRStatus_PCR_ENABLED
	} else {
		status.PCRStatus = info.PCRStatus_PCR_DISABLED
	}

	zfsEncryptStatus, zfsEncryptError := h.GetOperationalInfo()
	if zfsEncryptStatus != info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED {
		status.Status = zfsEncryptStatus
		status.SetErrorDescription(types.ErrorDescription{Error: zfsEncryptError})
	} else {
		if err := h.checkOperationalStatus(vaultPath); err != nil {
			h.log.Errorf("Status failed, %s", err)
			status.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR
			if status.PCRStatus == info.PCRStatus_PCR_ENABLED {
				if pcrs, err := etpm.FindMismatchingPCRs(); err == nil {
					status.MismatchingPCRs = pcrs
				}
			}
			errStr := err.Error()
			if pcrsStr := types.FormatMismatchingPCRs(status.MismatchingPCRs); pcrsStr != "" {
				errStr += "; " + pcrsStr
			}
			status.SetErrorDescription(types.ErrorDescription{Error: errStr})
		} else {
			h.log.Functionf("checkOperStatus returns ok for %s", vaultPath)
			status.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED
		}
	}
	return &status
}

// checkOperationalStatus returns nil if for vaultPath properties
// for in ZFS have the following values:
// mounted:yes keystatus:available encryption:aes-256-gcm;
// else return err
func (h *ZFSHandler) checkOperationalStatus(vaultPath string) error {
	dataset, err := libzfs.DatasetOpen(vaultPath)
	if err != nil {
		return err
	}
	defer dataset.Close()

	if dataset.Type == libzfs.DatasetTypeFilesystem {
		mounted, err := dataset.GetProperty(libzfs.DatasetPropMounted)
		if err != nil {
			return fmt.Errorf("DatasetExist(%s): Get property PropMounted failed. %s",
				vaultPath, err.Error())
		}

		//Expect mounted:yes keystatus:available encryption:aes-256-gcm
		if mounted.Value != "yes" {
			return fmt.Errorf("DatasetExist(%s): Dataset is not mounted. value: %s",
				vaultPath, mounted.Value)
		}
	}

	encryption, err := dataset.GetProperty(libzfs.DatasetPropEncryption)
	if err != nil {
		return fmt.Errorf("DatasetExist(%s): Get property Encryption failed. %s",
			vaultPath, err.Error())

	}

	// This property is not available for a dataset if no options associated
	// with the key were specified during it's creation.
	keyStatus, err := dataset.GetProperty(libzfs.DatasetPropKeyStatus)
	if err != nil {
		return fmt.Errorf("DatasetExist(%s): Get property KeyStatus failed. %s",
			vaultPath, err.Error())

	}

	if keyStatus.Value != "available" {
		return fmt.Errorf("DatasetExist(%s): Key is not loaded. value: %s",
			vaultPath, keyStatus.Value)
	}

	if encryption.Value != "aes-256-gcm" {
		return fmt.Errorf("DatasetExist(%s): Encryption is not enabled. value: %s",
			vaultPath, encryption.Value)
	}

	return nil
}

// waitPath - Wait up to the requested number of seconds for path to exist or return error
func waitPath(log *base.LogObject, path string, seconds int64) error {
	beginTime := time.Now().Unix()
	for {
		_, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				log.Warnf("waitPath path:%s missing", path)
				time.Sleep(1 * time.Second)
			}
		} else {
			return nil
		}
		if (time.Now().Unix() - beginTime) > seconds {
			break
		}
	}
	return fmt.Errorf("waitPath path %s not found after %d seconds", path, seconds)
}

// TrimVault reclaims blocks freed by ext4 that were never returned to the
// underlying ZFS zvol (ghost blocks). Only /persist/vault is trimmed here;
// the etcd-storage zvol is mounted at /var/lib inside the kube container,
// not the pillar container, so it is not reachable from this call site.
// No-op on non-EVE-k/non-ZFS handlers. timeout bounds the fstrim run;
// 0 means run to completion. Callers run this off the main goroutine.
func (h *ZFSHandler) TrimVault(timeout time.Duration) error {
	if !base.IsHVTypeKube() {
		return nil
	}

	timeoutDur := timeout
	timeoutDesc := timeout.String()
	if timeoutDur == 0 {
		timeoutDur = 365 * 24 * time.Hour
		timeoutDesc = "unlimited"
	}

	mountPoint := "/" + types.SealedDataset
	h.log.Noticef("TrimVault: starting fstrim %s (timeout %s)", mountPoint, timeoutDesc)
	start := time.Now()
	out, err := base.Exec(h.log, "fstrim", mountPoint).
		WithUnlimitedTimeout(timeoutDur).CombinedOutput()
	elapsed := time.Since(start)
	if err != nil {
		h.log.Errorf("TrimVault: fstrim %s failed after %s: %v (%s)", mountPoint, elapsed, err, out)
		return fmt.Errorf("fstrim %s failed after %s: %v (%s)", mountPoint, elapsed, err, out)
	}
	h.log.Noticef("TrimVault: fstrim %s completed in %s", mountPoint, elapsed)
	return nil
}

// MountVaultZvol Wrapper with wait for device
func MountVaultZvol(log *base.LogObject, datasetPath string) error {
	devPath := zfs.GetZvolPath(datasetPath)
	err := waitPath(log, devPath, vaultZvolPathWaitSeconds)
	if err != nil {
		return fmt.Errorf("Vault zvol dev path missing: %v", err)
	}

	_, err = os.Stat("/" + types.SealedDataset)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.Mkdir("/"+types.SealedDataset, os.FileMode(755))
			if err != nil {
				return fmt.Errorf("MountVaultZvol path %s creation error: %v", "/"+types.SealedDataset, err)
			}
		}
	}

	mountFlags := uintptr(unix.MS_DIRSYNC | unix.MS_NOATIME)
	if noDirsyncRequested() {
		mountFlags = unix.MS_NOATIME
	}
	err = unix.Mount(devPath, "/"+types.SealedDataset, vaultFsType, mountFlags, "")
	if err != nil {
		return fmt.Errorf("mount of %s to %s err:%v", devPath, "/"+types.SealedDataset, err)
	}
	return nil
}

func noDirsyncRequested() bool {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return false
	}
	for _, arg := range strings.Fields(string(data)) {
		if arg == cmdlineNoDirsync {
			return true
		}
	}
	return false
}

// formatZvol apply an ext4 fs to the device path given
func formatZvol(log *base.LogObject, zvolDevPath string, fsType string) error {
	// Not enabling encryption...its already set on the zvol
	ctx := context.Background()
	args := []string{zvolDevPath}
	output, err := base.Exec(log, "/sbin/mkfs."+fsType, args...).WithContext(ctx).WithUnlimitedTimeout(3600 * time.Second).CombinedOutput()
	if err != nil {
		return fmt.Errorf("formatZvol dev:%s, stdout:%s, err:%v", zvolDevPath, output, err)
	}
	return nil
}

// CreateZvolVault Create and mount an empty vault dataset zvol
func CreateZvolVault(log *base.LogObject, datasetName string, zfsKeyFile string, encrypted bool) error {
	// Remaining space in the pool
	sizeBytes := uint64(0)

	parentDatasetName := datasetName
	if strings.Contains(parentDatasetName, "/") {
		datasetParts := strings.Split(parentDatasetName, "/")
		parentDatasetName = datasetParts[0]
	}

	sizeBytes, err := zfs.GetDatasetAvailableBytes(parentDatasetName)
	if err != nil {
		return fmt.Errorf("Dataset %s available bytes read error: %v", parentDatasetName, err)
	}
	// Shift back to allow for alignUp space.
	sizeBytes = sizeBytes - zfs.VolBlockSizeBytes

	err = zfs.CreateVaultVolumeDataset(log, datasetName, zfsKeyFile, encrypted, sizeBytes, "zstd", zfs.VolBlockSizeBytes)
	if err != nil {
		return fmt.Errorf("Vault zvol creation error; %v", err)
	}

	devPath := zfs.GetZvolPath(types.SealedDataset)
	// Sometimes we wait for /dev path to the zvol to appear
	// Since this only occurs on first boot, we can afford to be patient
	if err = waitPath(log, devPath, vaultZvolPathWaitSeconds); err != nil {
		return fmt.Errorf("Vault zvol dev path missing: %v", err)
	}

	if err = formatZvol(log, devPath, vaultFsType); err != nil {
		return fmt.Errorf("Vault zvol format error: %v", err)
	}

	if err = MountVaultZvol(log, types.SealedDataset); err != nil {
		return fmt.Errorf("Vault zvol mount error: %v", err)
	}
	return nil
}

// CreateZvolEtcd Create and mount an empty vault dataset zvol
func CreateZvolEtcd(log *base.LogObject, datasetName string, zfsKeyFile string, encrypted bool) error {
	etcdSizeGb, err := getEtcdSizeSetting()
	if err != nil {
		log.Errorf("Using default %d GB, can't read etcd size setting: %v", etcdSizeGb, err)
	}
	etcdSizeBytes := uint64(1024 * 1024 * 1024 * uint64(etcdSizeGb))

	err = zfs.CreateVaultVolumeDataset(log, datasetName, zfsKeyFile, encrypted, etcdSizeBytes, "off", base.EtcdVolBlockSizeBytes)
	if err != nil {
		return fmt.Errorf("Vault Etcd zvol creation error: %v", err)
	}

	devPath := zfs.GetZvolPath(datasetName)
	// Sometimes we wait for /dev path to the zvol to appear
	// Since this only occurs on first boot, we can afford to be patient
	if err = waitPath(log, devPath, vaultZvolPathWaitSeconds); err != nil {
		return fmt.Errorf("Vault Etcd zvol dev path missing: %v", err)
	}

	if err = formatZvol(log, devPath, vaultFsType); err != nil {
		return fmt.Errorf("Vault Etcd zvol format error: %v", err)
	}
	return nil
}

func getEtcdSizeSetting() (uint32, error) {
	size := base.DefaultEtcdSizeGB
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return size, err
	}
	bootArgs := strings.Fields(string(data))
	for _, arg := range bootArgs {
		if strings.HasPrefix(arg, base.InstallOptionEtcdSizeGB) {
			argSplitted := strings.Split(arg, "=")
			if len(argSplitted) == 2 {
				valGB, err := strconv.ParseUint(argSplitted[1], 10, 32)
				if err == nil {
					return uint32(valGB), nil
				}
				return size, err
			}
		}
	}
	return size, nil
}
