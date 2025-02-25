// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/stretchr/testify/assert"
)

func TestPCIReadResources(t *testing.T) {
	t.Parallel()
	// Create a temporary directory for our fake sysfs
	tempDir, err := os.MkdirTemp("", "test-pci")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir) // Cleanup after test

	// Create a fake PCI device directory
	devicePath := filepath.Join(tempDir, "0000:00:1f.0")
	err = os.MkdirAll(devicePath, 0755)
	assert.NoError(t, err)

	// Create mock resource file
	resourceContent := "0x00000000fed40000 0x00000000fed44fff 0x0000000000040200\n" +
		"0x00000000fec00000 0x00000000fec003ff 0x0000000000040200\n"

	err = os.WriteFile(filepath.Join(devicePath, "resource"), []byte(resourceContent), 0644)
	assert.NoError(t, err)

	deviceAttributes := []string{"resource0", "resource1", "resource1_wc", "resource1_resize", "resource1_not_yet_exist"}

	for _, attr := range deviceAttributes {
		err = os.WriteFile(filepath.Join(devicePath, attr), []byte{}, 0644)
		assert.NoError(t, err)
	}

	// Instantiate the PCI device and call readResources()
	pciDev := pciDevice{ioBundle: types.IoBundle{PciLong: "0000:00:1f.0"}}
	resources, err := pciDev.readResources(tempDir)

	// Assertions
	assert.NoError(t, err)
	assert.Len(t, resources, 2)

	assert.Equal(t, uint64(0xfed40000), resources[0].start)
	assert.Equal(t, uint64(0xfed44fff), resources[0].end)
	assert.Equal(t, uint64(0x00040200), resources[0].flags)
	assert.Equal(t, 0, resources[0].index)

	assert.Equal(t, uint64(0xfec00000), resources[1].start)
	assert.Equal(t, uint64(0xfec003ff), resources[1].end)
	assert.Equal(t, uint64(0x00040200), resources[1].flags)
	assert.Equal(t, 1, resources[1].index)
}
