// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupFakeIOMMUSysfs creates a temporary sysfs tree for IOMMU group tests
// and returns an iommuGroupContext pointing at it.
func setupFakeIOMMUSysfs(t *testing.T) (iommuGroupContext, string) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "iommu-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	pciDevicesDir := filepath.Join(tmpDir, "bus/pci/devices")
	iommuGroupsDir := filepath.Join(tmpDir, "kernel/iommu_groups")
	vfioDriverDir := filepath.Join(tmpDir, "bus/pci/drivers/vfio-pci")
	driversProbe := filepath.Join(tmpDir, "bus/pci/drivers_probe")

	require.NoError(t, os.MkdirAll(pciDevicesDir, 0755))
	require.NoError(t, os.MkdirAll(iommuGroupsDir, 0755))
	require.NoError(t, os.MkdirAll(vfioDriverDir, 0755))
	require.NoError(t, os.WriteFile(driversProbe, nil, 0644))

	ctx := iommuGroupContext{
		pciDevicesDir:  pciDevicesDir,
		iommuGroupsDir: iommuGroupsDir,
		vfioDriverDir:  vfioDriverDir,
		driversProbe:   driversProbe,
	}
	return ctx, tmpDir
}

// addDeviceToGroup creates a fake PCI device directory with an iommu_group
// symlink and registers it in the group's devices directory.
func addDeviceToGroup(t *testing.T, ctx *iommuGroupContext, addr, group string) {
	t.Helper()
	devDir := filepath.Join(ctx.pciDevicesDir, addr)
	require.NoError(t, os.MkdirAll(devDir, 0755))

	groupDevicesDir := filepath.Join(ctx.iommuGroupsDir, group, "devices")
	require.NoError(t, os.MkdirAll(groupDevicesDir, 0755))

	// iommu_group symlink — os.Readlink returns the target, filepath.Base extracts group number
	iommuGroupTarget := filepath.Join(ctx.iommuGroupsDir, group)
	require.NoError(t, os.Symlink(iommuGroupTarget, filepath.Join(devDir, "iommu_group")))

	// Register device in group's devices directory
	require.NoError(t, os.WriteFile(filepath.Join(groupDevicesDir, addr), nil, 0644))
}

// bindToKernelDriver simulates a kernel driver binding by creating a driver
// directory with an unbind file and symlinking device/driver to it.
func bindToKernelDriver(t *testing.T, ctx *iommuGroupContext, tmpDir, addr, driverName string) {
	t.Helper()
	driverDir := filepath.Join(tmpDir, "bus/pci/drivers", driverName)
	require.NoError(t, os.MkdirAll(driverDir, 0755))

	unbindFile := filepath.Join(driverDir, "unbind")
	if _, err := os.Stat(unbindFile); err != nil {
		require.NoError(t, os.WriteFile(unbindFile, nil, 0644))
	}
	require.NoError(t, os.Symlink(driverDir, filepath.Join(ctx.pciDevicesDir, addr, "driver")))
}

// bindToVfioPci simulates vfio-pci driver binding.
func bindToVfioPci(t *testing.T, ctx *iommuGroupContext, addr string) {
	t.Helper()
	require.NoError(t, os.Symlink(ctx.vfioDriverDir, filepath.Join(ctx.pciDevicesDir, addr, "driver")))
}

func TestGetIOMMUGroup(t *testing.T) {
	ctx, _ := setupFakeIOMMUSysfs(t)
	addDeviceToGroup(t, &ctx, "0000:80:1f.6", "19")

	group, err := ctx.getIOMMUGroup("0000:80:1f.6")
	require.NoError(t, err)
	assert.Equal(t, "19", group)
}

func TestGetIOMMUGroupNoSymlink(t *testing.T) {
	ctx, _ := setupFakeIOMMUSysfs(t)
	// Device exists but has no iommu_group symlink
	require.NoError(t, os.MkdirAll(filepath.Join(ctx.pciDevicesDir, "0000:00:01.0"), 0755))

	_, err := ctx.getIOMMUGroup("0000:00:01.0")
	assert.Error(t, err)
}

func TestGetMembers(t *testing.T) {
	ctx, _ := setupFakeIOMMUSysfs(t)
	addDeviceToGroup(t, &ctx, "0000:80:1f.0", "19")
	addDeviceToGroup(t, &ctx, "0000:80:1f.4", "19")
	addDeviceToGroup(t, &ctx, "0000:80:1f.6", "19")

	members, err := ctx.getMembers("0000:80:1f.6")
	require.NoError(t, err)
	sort.Strings(members)
	assert.Equal(t, []string{"0000:80:1f.0", "0000:80:1f.4", "0000:80:1f.6"}, members)
}

func TestGetMembersSingleDevice(t *testing.T) {
	ctx, _ := setupFakeIOMMUSysfs(t)
	addDeviceToGroup(t, &ctx, "0000:01:00.0", "5")

	members, err := ctx.getMembers("0000:01:00.0")
	require.NoError(t, err)
	assert.Equal(t, []string{"0000:01:00.0"}, members)
}

func TestIsBoundToVfioPci(t *testing.T) {
	ctx, tmpDir := setupFakeIOMMUSysfs(t)
	addDeviceToGroup(t, &ctx, "0000:80:1f.6", "19")
	addDeviceToGroup(t, &ctx, "0000:80:1f.4", "19")
	addDeviceToGroup(t, &ctx, "0000:80:1f.0", "19")

	// Bound to vfio-pci
	bindToVfioPci(t, &ctx, "0000:80:1f.6")
	assert.True(t, ctx.isBoundToVfioPci("0000:80:1f.6"))

	// Bound to a kernel driver
	bindToKernelDriver(t, &ctx, tmpDir, "0000:80:1f.4", "i801_smbus")
	assert.False(t, ctx.isBoundToVfioPci("0000:80:1f.4"))

	// Not bound to any driver
	assert.False(t, ctx.isBoundToVfioPci("0000:80:1f.0"))
}

func TestUnbindSiblings(t *testing.T) {
	ctx, tmpDir := setupFakeIOMMUSysfs(t)
	addDeviceToGroup(t, &ctx, "0000:80:1f.0", "19")
	addDeviceToGroup(t, &ctx, "0000:80:1f.4", "19")
	addDeviceToGroup(t, &ctx, "0000:80:1f.5", "19")
	addDeviceToGroup(t, &ctx, "0000:80:1f.6", "19")

	// Target device bound to vfio-pci (should be skipped)
	bindToVfioPci(t, &ctx, "0000:80:1f.6")
	// Kernel driver siblings (should be unbound)
	bindToKernelDriver(t, &ctx, tmpDir, "0000:80:1f.0", "lpc_ich")
	bindToKernelDriver(t, &ctx, tmpDir, "0000:80:1f.4", "i801_smbus")
	// 80:1f.5 has no driver (should be skipped)

	ctx.unbindSiblings("0000:80:1f.6")

	// Verify unbind was written for kernel driver siblings
	lpcUnbind := filepath.Join(tmpDir, "bus/pci/drivers/lpc_ich/unbind")
	content, err := os.ReadFile(lpcUnbind)
	require.NoError(t, err)
	assert.Equal(t, "0000:80:1f.0", string(content))

	i801Unbind := filepath.Join(tmpDir, "bus/pci/drivers/i801_smbus/unbind")
	content, err = os.ReadFile(i801Unbind)
	require.NoError(t, err)
	assert.Equal(t, "0000:80:1f.4", string(content))
}

func TestUnbindSiblingsSkipsVfioPci(t *testing.T) {
	ctx, _ := setupFakeIOMMUSysfs(t)
	addDeviceToGroup(t, &ctx, "0000:80:1f.4", "19")
	addDeviceToGroup(t, &ctx, "0000:80:1f.6", "19")

	// Both bound to vfio-pci — no unbind should happen
	bindToVfioPci(t, &ctx, "0000:80:1f.6")
	bindToVfioPci(t, &ctx, "0000:80:1f.4")

	// Should not panic or error
	ctx.unbindSiblings("0000:80:1f.6")
}

func TestReprobeSiblings(t *testing.T) {
	ctx, tmpDir := setupFakeIOMMUSysfs(t)
	addDeviceToGroup(t, &ctx, "0000:80:1f.0", "19")
	addDeviceToGroup(t, &ctx, "0000:80:1f.4", "19")
	addDeviceToGroup(t, &ctx, "0000:80:1f.6", "19")

	// 80:1f.6 is the target (skip)
	// 80:1f.0 already has a driver rebound (skip)
	someDriverDir := filepath.Join(tmpDir, "bus/pci/drivers/some_driver")
	require.NoError(t, os.MkdirAll(someDriverDir, 0755))
	require.NoError(t, os.Symlink(someDriverDir, filepath.Join(ctx.pciDevicesDir, "0000:80:1f.0", "driver")))
	// 80:1f.4 has no driver (should be re-probed)

	ctx.reprobeSiblings("0000:80:1f.6")

	// Verify drivers_probe was written with the unbound device address
	content, err := os.ReadFile(ctx.driversProbe)
	require.NoError(t, err)
	assert.Equal(t, "0000:80:1f.4", string(content))
}

func TestReprobeSiblingsAllBound(t *testing.T) {
	ctx, tmpDir := setupFakeIOMMUSysfs(t)
	addDeviceToGroup(t, &ctx, "0000:80:1f.4", "19")
	addDeviceToGroup(t, &ctx, "0000:80:1f.6", "19")

	// Both have drivers — nothing to reprobe
	bindToKernelDriver(t, &ctx, tmpDir, "0000:80:1f.4", "i801_smbus")
	bindToVfioPci(t, &ctx, "0000:80:1f.6")

	ctx.reprobeSiblings("0000:80:1f.6")

	// drivers_probe should remain empty
	content, err := os.ReadFile(ctx.driversProbe)
	require.NoError(t, err)
	assert.Empty(t, content)
}
