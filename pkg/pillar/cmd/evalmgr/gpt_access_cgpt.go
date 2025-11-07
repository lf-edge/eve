// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/zboot"
)

// getRootDisk returns the parent disk device using current partition device from zboot
// E.g., if current partition is /dev/sda3, returns /dev/sda
func getRootDisk() (string, error) {
	// Use zboot to get current partition device
	currentPartDev := zboot.GetCurrentPartitionDevName()
	if currentPartDev == "" {
		return "", fmt.Errorf("failed to get current partition device")
	}

	// Use lsblk to find parent disk
	cmd := exec.Command("lsblk", "-no", "pkname", currentPartDev)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get parent disk for %s: %w", currentPartDev, err)
	}

	pkname := strings.TrimSpace(string(output))
	if pkname == "" {
		return "", fmt.Errorf("parent disk not found for %s", currentPartDev)
	}

	return "/dev/" + pkname, nil
}

// getPartitionNumber returns the partition number for a given label and disk
// Uses cgpt find to locate partition by label
func getPartitionNumber(label string, disk string) (int, error) {
	// Execute: cgpt find -l <label> -n <disk>
	cmd := exec.Command("cgpt", "find", "-l", label, "-n", disk)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("cgpt find failed for label %s: %w, output: %s", label, err, string(output))
	}

	partNumStr := strings.TrimSpace(string(output))
	partNum, err := strconv.Atoi(partNumStr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse partition number '%s' for label %s: %w", partNumStr, label, err)
	}

	return partNum, nil
}

// getPartitionAttributes reads the raw GPT attribute value for a partition
// Returns the 16-bit attribute value as read by cgpt
func getPartitionAttributes(slot string) (uint16, error) {
	// Get parent disk
	rootDisk, err := getRootDisk()
	if err != nil {
		return 0, fmt.Errorf("failed to get root disk: %w", err)
	}

	// Get partition number
	partNum, err := getPartitionNumber(slot, rootDisk)
	if err != nil {
		return 0, err
	}

	// Execute: cgpt show -i <partition_num> -A <device>
	cmd := exec.Command("cgpt", "show", "-i", strconv.Itoa(partNum), "-A", rootDisk)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("cgpt show failed for slot %s: %w, output: %s", slot, err, string(output))
	}

	// Parse output - cgpt returns hex like "0x102" or decimal
	attrStr := strings.TrimSpace(string(output))

	// Handle hex format (0x...)
	var attr uint64
	if strings.HasPrefix(attrStr, "0x") || strings.HasPrefix(attrStr, "0X") {
		attr, err = strconv.ParseUint(attrStr, 0, 16)
	} else {
		attr, err = strconv.ParseUint(attrStr, 10, 16)
	}

	if err != nil {
		return 0, fmt.Errorf("failed to parse cgpt attribute '%s' for slot %s: %w", attrStr, slot, err)
	}

	log.Functionf("getPartitionAttributes: slot=%s partition=%d disk=%s attr=0x%03x", slot, partNum, rootDisk, attr)
	return uint16(attr), nil
}

// setPartitionAttributes writes the raw GPT attribute value for a partition
// The attr parameter is a 16-bit value with priority, tries, and successful bits
func setPartitionAttributes(slot string, attr uint16) error {
	// Get parent disk
	rootDisk, err := getRootDisk()
	if err != nil {
		return fmt.Errorf("failed to get root disk: %w", err)
	}

	// Get partition number
	partNum, err := getPartitionNumber(slot, rootDisk)
	if err != nil {
		return err
	}

	// Extract individual fields from the 16-bit attribute
	priority := int(attr & 0x0F)          // Bits 0-3
	tries := int((attr >> 4) & 0x0F)      // Bits 4-7
	successful := int((attr >> 8) & 0x01) // Bit 8

	log.Functionf("setPartitionAttributes: slot=%s partition=%d disk=%s attr=0x%03x (priority=%d, tries=%d, successful=%d)",
		slot, partNum, rootDisk, attr, priority, tries, successful)

	// Execute: cgpt add -i <partition_num> -P <priority> -T <tries> -S <successful> <device>
	cmd := exec.Command("cgpt", "add",
		"-i", strconv.Itoa(partNum),
		"-P", strconv.Itoa(priority),
		"-T", strconv.Itoa(tries),
		"-S", strconv.Itoa(successful),
		rootDisk)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cgpt add failed for slot %s: %w, output: %s", slot, err, string(output))
	}

	return nil
}

// CgptAccess implements GptAttributeAccess using real cgpt commands
// This is the production implementation that reads/writes GPT partition attributes
type CgptAccess struct {
	// No state needed - all data is in GPT on disk
}

// NewCgptAccess creates a new CGPT-based partition attribute accessor
func NewCgptAccess() *CgptAccess {
	return &CgptAccess{}
}

// GetPartitionAttributes reads the raw GPT attribute value for a partition
// Uses cgpt command to read from actual disk
func (c *CgptAccess) GetPartitionAttributes(partition string) (uint16, error) {
	return getPartitionAttributes(partition)
}

// SetPartitionAttributes writes the raw GPT attribute value for a partition
// Uses cgpt command to write to actual disk
func (c *CgptAccess) SetPartitionAttributes(partition string, attr uint16) error {
	return setPartitionAttributes(partition, attr)
}

// GetCurrentPartition returns the label of the currently booted partition
func (c *CgptAccess) GetCurrentPartition() string {
	return zboot.GetCurrentPartition()
}

// GetValidPartitionLabels returns all valid partition labels for this platform
func (c *CgptAccess) GetValidPartitionLabels() []string {
	return zboot.GetValidPartitionLabels()
}
