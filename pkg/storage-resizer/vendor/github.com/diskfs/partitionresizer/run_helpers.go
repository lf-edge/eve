package partitionresizer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/diskfs/go-diskfs/disk"
	"github.com/diskfs/go-diskfs/partition/gpt"
)

const (
	partTmpFilename = "partresizer-shrinkfs-XXXXXXXX"
)

// runTool runs an external filesystem tool, streaming its output live to the
// process's stdout/stderr while also capturing stderr. On a non-zero exit the
// returned error wraps the exit status and includes the tool's own stderr
// diagnostic, so a programmatic caller gets the reason for the failure rather
// than a bare "exit status N".
func runTool(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			const max = 2000
			if len(msg) > max {
				msg = "..." + msg[len(msg)-max:]
			}
			return fmt.Errorf("%s failed: %w\n%s", name, err, msg)
		}
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

// execE2fsck runs a forced e2fsck on the given device or image file. By default
// it is read-only (-n) and returns an error if the filesystem is inconsistent;
// with fixErrors it repairs in place (-y).
var execE2fsck = func(partDevice string, fixErrors bool) error {
	fixFlag := "-n"
	if fixErrors {
		fixFlag = "-y"
	}
	err := runTool("e2fsck", "-f", fixFlag, partDevice)
	if err == nil || !fixErrors {
		return err
	}
	// e2fsck's exit status is a bitmask: bit 0 (1) = filesystem errors were
	// corrected, bit 1 (2) = corrected and a reboot is advised, bit 2 (4) =
	// errors left UNcorrected, higher bits = operational/usage errors. When we
	// asked it to repair (-y) -- e.g. recovering a dirty journal after a power
	// loss, which is exactly the case this resizer must survive -- "corrected"
	// is success. Only uncorrected (>=4) or operational errors are real failures.
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode()&^0x3 == 0 {
		log.Printf("e2fsck repaired %s (exit %d); filesystem now clean, continuing", partDevice, ee.ExitCode())
		return nil
	}
	return err
}

// execFsckFat runs fsck.fat on the given device or image file. By default it is
// read-only (-n) and returns an error if the filesystem is inconsistent; with
// fixErrors it auto-repairs (-a).
var execFsckFat = func(partDevice string, fixErrors bool) error {
	fixFlag := "-n"
	if fixErrors {
		fixFlag = "-a"
	}
	return runTool("fsck.fat", fixFlag, partDevice)
}

// execResize2fs is the function used to invoke resize2fs. partDevice may be a block device pointing to the actual
// filesystem partition, or an image file with the filesystem at byte 0. resize2fs requires a clean filesystem, so
// e2fsck is always run first.
var execResize2fs = func(partDevice string, newSizeMB int64, fixErrors bool) error {
	if err := execE2fsck(partDevice, fixErrors); err != nil {
		return err
	}
	return runTool("resize2fs", partDevice, fmt.Sprintf("%dM", newSizeMB))
}

// resizeFilesystem resizes an ext4 filesystem, given a full path to the device and partition data
// Should account for it being a disk image with multiple partitions if needed, i.e. not just an entire disk,
// using the information in filesystemData.
// filesystemData is expected to be the *current* partition data, i.e. before resizing,
// while delta is the expected delta in size.
func resizeFilesystem(
	device string,
	filesystemData partitionData,
	delta int64,
	fixErrors bool,
) error {
	newSize := filesystemData.size + delta
	newSizeMB := newSize / (1024 * 1024)
	log.Printf(
		"Resizing filesystem on partition %d to %d MB",
		filesystemData.number, newSizeMB,
	)
	f, err := os.Open(device)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	deviceType, err := disk.DetermineDeviceType(f)
	if err != nil {
		return err
	}
	switch deviceType {
	case disk.DeviceTypeBlockDevice:
		// resize2fs takes the *partition* device, not the whole-disk
		// device, so we resolve "/dev/sda" + partition number 9 to
		// "/dev/sda9" (or whatever the kernel calls that slot —
		// "/dev/nvme0n1p9", "/dev/mmcblk0p9", etc.) via sysfs.
		partDevice, err := partitionDevicePath(device, filesystemData.number, "")
		if err != nil {
			return fmt.Errorf("cannot find partition device for %s partition %d: %w", device, filesystemData.number, err)
		}
		return execResize2fs(partDevice, newSizeMB, fixErrors)
	case disk.DeviceTypeFile:
		// copy the partition, then resize it, then copy it back into the original disk image
		tmpFile, err2 := os.CreateTemp("", partTmpFilename)
		if err2 != nil {
			return err2
		}
		_ = tmpFile.Close()
		defer func() {
			_ = os.RemoveAll(tmpFile.Name())
		}()
		// copy the file over
		if err = CopyRange(device, tmpFile.Name(), filesystemData.start, 0, filesystemData.size, 0); err != nil {
			return fmt.Errorf("copy to temp file: %w", err)
		}
		if err = execResize2fs(tmpFile.Name(), newSizeMB, fixErrors); err != nil {
			return err
		}
		err = CopyRange(tmpFile.Name(), device, 0, filesystemData.start, newSize, 0)
	case disk.DeviceTypeUnknown:
		err = fmt.Errorf("unknown device type for %s", device)
	}
	return err
}

// checkFilesystem runs the given filesystem checker (e.g. execE2fsck,
// execFsckFat) against the filesystem in the given partition. device is the
// whole-disk device or image file; fsData describes the partition. The caller
// selects fsck based on filesystem type; checkFilesystem only handles locating
// the filesystem on the disk. The check is read-only unless fixErrors is set.
// It mirrors resizeFilesystem's block-device-vs-image dispatch: for a block
// device the partition's device node is checked directly; for an image file the
// partition byte-range is extracted to a temp file, checked, and -- only when
// repairing -- copied back.
func checkFilesystem(device string, fsData partitionData, fsck func(string, bool) error, fixErrors bool) error {
	f, err := os.Open(device)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	deviceType, err := disk.DetermineDeviceType(f)
	if err != nil {
		return err
	}
	switch deviceType {
	case disk.DeviceTypeBlockDevice:
		partDevice, err := partitionDevicePath(device, fsData.number, "")
		if err != nil {
			return fmt.Errorf("cannot find partition device for %s partition %d: %w", device, fsData.number, err)
		}
		return fsck(partDevice, fixErrors)
	case disk.DeviceTypeFile:
		tmpFile, err := os.CreateTemp("", partTmpFilename)
		if err != nil {
			return err
		}
		_ = tmpFile.Close()
		defer func() { _ = os.RemoveAll(tmpFile.Name()) }()
		if err := CopyRange(device, tmpFile.Name(), fsData.start, 0, fsData.size, 0); err != nil {
			return fmt.Errorf("copy to temp file: %w", err)
		}
		if err := fsck(tmpFile.Name(), fixErrors); err != nil {
			return err
		}
		// Only a repairing run mutates the filesystem; persist it back into
		// the image. A read-only check leaves the source untouched.
		if fixErrors {
			return CopyRange(tmpFile.Name(), device, 0, fsData.start, fsData.size, 0)
		}
		return nil
	case disk.DeviceTypeUnknown:
		return fmt.Errorf("unknown device type for %s", device)
	}
	return nil
}

// planResizes computes the resize plan, including both growing the relevant partitions as well as
// optionally performing an ext4 shrink, if there is insufficient space initially.
// Returns the final plan or an error.
func planResizes(
	d *disk.Disk,
	table *gpt.Table,
	diskPartitionData []partitionData,
	growPartitions []PartitionChange,
	shrinkPartition *PartitionIdentifier,
) (
	[]partitionResizeTarget,
	error,
) {
	// map PartitionChange to partitionResizeTarget
	prTargets, err := partitionChangesToResizeTarget(table, diskPartitionData, growPartitions)
	if err != nil {
		return nil, err
	}

	// Resume support: an interrupted run may already have created the relocated
	// "<label>_resized2" partition for some grows. Those targets already occupy
	// their final space, so they must be excluded from (re)planning. If we
	// instead fed them back through calculateResizes, their space would count as
	// occupied, the grow would no longer fit, and a second shrink of the shrink
	// partition would be planned -- driving its size negative
	// (diskfs/partitionresizer#13). Split the grows already created from those
	// still pending, and reuse the existing partition's geometry as the target
	// for the created ones.
	existingByName := make(map[string]*gpt.Partition)
	for _, p := range table.Partitions {
		if p.Type == gpt.Unused {
			continue
		}
		existingByName[p.Name] = p
	}
	var done, pending []partitionResizeTarget
	for _, pr := range prTargets {
		// Already at the requested size: nothing to do. This is a grow that a
		// prior, interrupted run already finished (the label now resolves to the
		// finalized, grown partition), or simply a no-op request. A genuine
		// shrink (original larger than target) is left to calculateResizes.
		if pr.original.size == pr.target.size {
			continue
		}
		alt, ok := existingByName[getAlternateLabel(pr.original.label)]
		if !ok {
			pending = append(pending, pr)
			continue
		}
		start := alt.GetStart()
		size := int64(alt.GetSize())
		pr.target = partitionData{
			label:  alt.Name,
			size:   size,
			start:  start,
			end:    start + size - 1,
			number: alt.Index,
		}
		done = append(done, pr)
	}

	// every grow is already created: nothing left to allocate or shrink
	if len(pending) == 0 {
		return done, nil
	}

	// try to calculate without shrinking, for the pending grows only
	resizes, err := calculateResizes(d.Size, table.Partitions, pending)
	if err == nil {
		return append(done, resizes...), nil
	}
	var spaceErr *InsufficientSpaceError
	if !errors.As(err, &spaceErr) {
		return nil, err
	}

	// need to shrink: ensure shrinkPartition provided
	if shrinkPartition == nil {
		return nil, fmt.Errorf("insufficient space to perform requested partition grows, and no shrink partition specified")
	}

	// compute total space to grow (rounded up to next GB) for the pending grows
	var totalGrow int64
	for _, gp := range pending {
		totalGrow += gp.target.size
	}
	if totalGrow%GB != 0 {
		totalGrow = ((totalGrow / GB) + 1) * GB
	}

	// locate shrink partition data
	shrinkDataList, err := partitionIdentifiersToData(table, diskPartitionData, []PartitionIdentifier{*shrinkPartition})
	if err != nil {
		return nil, err
	}
	if len(shrinkDataList) != 1 {
		return nil, fmt.Errorf("could not find shrink partition data")
	}
	shrinkData := shrinkDataList[0]

	// mark the shrink as first for the resize
	target := shrinkData
	target.size = shrinkData.size - totalGrow
	target.end = shrinkData.end - totalGrow
	shrink := partitionResizeTarget{
		original: shrinkData,
		target:   target,
	}
	prTargetsWithShrink := []partitionResizeTarget{shrink}
	prTargetsWithShrink = append(prTargetsWithShrink, pending...)

	// recalculate resizes with shrinking
	resizes, err = calculateResizes(d.Size, table.Partitions, prTargetsWithShrink)
	if err != nil {
		return nil, err
	}
	return append(done, resizes...), nil
}

// partitionDevicePath maps a whole-disk path (e.g. "/dev/sda") and a
// partition number to the partition's device path (e.g. "/dev/sda9",
// "/dev/nvme0n1p9", "/dev/mmcblk0p9").
//
// Naming conventions for partition device nodes differ by disk type,
// so we look up the kernel partition name via sysfs rather than
// hardcoding the convention: each /sys/class/block/<disk>/<part>/
// directory holds a "partition" file containing the partition number
// and a directory named after the kernel partition name.
//
// If syspath is empty, /sys is used. Returns an error if no matching
// partition is found under sysfs.
func partitionDevicePath(diskPath string, partNumber int, syspath string) (string, error) {
	if syspath == "" {
		syspath = sysDefaultPath
	}
	diskBase := filepath.Base(diskPath)
	diskSysDir := filepath.Join(syspath, "class", "block", diskBase)
	entries, err := os.ReadDir(diskSysDir)
	if err != nil {
		return "", fmt.Errorf("read sysfs dir %s: %w", diskSysDir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		partFile := filepath.Join(diskSysDir, e.Name(), "partition")
		raw, err := os.ReadFile(partFile)
		if err != nil {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil {
			continue
		}
		if n == partNumber {
			return filepath.Join("/dev", e.Name()), nil
		}
	}
	return "", fmt.Errorf("partition %d not found under %s", partNumber, diskSysDir)
}
