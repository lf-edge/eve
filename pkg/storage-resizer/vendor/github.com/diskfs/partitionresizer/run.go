package partitionresizer

import (
	"fmt"
	"log"

	"github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/partition/gpt"
)

// Run performs the partition resizing operations on the specified disk image or device.
// The shrinkPartition may be nil if no shrinking is to be performed. If it is provided, and there is not enough
// space for the grow operations, then it will attempt to shrink the specified partition to make room, but only
// if it has an identifiable ext4 filesystem to shrink, and there is enough space to shrink it.
// It always will try to run e2fsck before shrinking. By default, it will not fix any found errors, in which case it will
// error out if any filesystem errors are found. If fixErrors is true, it will attempt to fix any found errors.
// If preserveNumbers is true, any partition that is relocated while growing is renumbered back to its original
// partition number once the data has been copied, so its partition number (e.g. /dev/sda2) is unchanged by the resize.
//
// Pre-flight integrity checks. Before any destructive operation, Run
// integrity-checks every source filesystem it will read or modify -- the shrink
// partition and each grow source. ext4 sources are checked with e2fsck and
// fat32 sources with fsck.fat; by default the checks are read-only and an
// inconsistent filesystem aborts the resize, while fixErrors upgrades them to
// repair (e2fsck -y / fsck.fat -a). squashfs sources (read-only,
// content-addressed, copied raw) have no applicable check and are copied as-is,
// so a corrupt squashfs source is reproduced faithfully. Run does NOT perform
// usage-specific pre-flight checks such as free-space policy; that remains the
// caller's responsibility. When resuming a previously-interrupted run, Run
// reuses an already-written target only when it structurally matches its source
// via CompareFS; that comparison is a structure/content equality check, not a
// filesystem integrity check.
func Run(disk string, shrinkPartition *PartitionIdentifier, growPartitions []PartitionChange, fixErrors, dryRun, preserveNumbers bool) error {
	// we always work solely with partition UUIDs internally, so convert any other identifiers to UUIDs
	// see if a disk was specified
	// no disk specified, try to discover
	var err error
	var partIdentifiers []PartitionIdentifier
	if shrinkPartition != nil {
		partIdentifiers = append(partIdentifiers, *shrinkPartition)
	}
	for _, gp := range growPartitions {
		partIdentifiers = append(partIdentifiers, gp)
	}
	disks, err := findDisks(disk, "")
	if err != nil {
		return fmt.Errorf("failed to find disks: %v", err)
	}
	filteredDisks, err := filterDisksByPartitions(disks, partIdentifiers)
	if err != nil {
		return fmt.Errorf("failed to filter disks by partiton: %v", err)
	}
	if len(filteredDisks) == 0 {
		return fmt.Errorf("no disks found matching specified partitions")
	}
	if len(filteredDisks) > 1 {
		return fmt.Errorf("multiple disks found matching specified partitions: %+v", filteredDisks)
	}
	matchedDisk := filteredDisks[0]
	diskPartitionData := disks[matchedDisk]
	log.Printf("Using disk: %s via path %s", matchedDisk, disk)

	// now we have the desired disk, either passed explicitly or found by discovery

	// Open the whole disk read-write but NOT O_EXCL. partitionresizer shells out
	// to e2fsck/resize2fs/fsck.fat on the child partitions, which open those
	// partitions O_EXCL. On a real block device, holding the parent disk O_EXCL
	// makes those child opens fail with "device is in use" (the kernel's
	// partition claim hierarchy). OpenFromPathWithExclusive(..., false) opens
	// non-exclusively while still recording the path (which the source-filesystem
	// checks need). The caller guarantees the partitions are unmounted.
	backendFile, err := file.OpenFromPathWithExclusive(disk, false, false)
	if err != nil {
		return err
	}
	// maybeWrapBackend is a no-op in normal builds; in -tags chaos builds it can
	// inject delays around GPT-sector writes (see RESIZER_GPT_WRITE_DELAY) so
	// crash-injection tests can land between the backup/primary GPT writes.
	d, err := diskfs.OpenBackend(maybeWrapBackend(backendFile))
	if err != nil {
		return err
	}

	// get the table and partition information
	tableRaw, err := d.GetPartitionTable()
	if err != nil {
		return err
	}
	table, ok := tableRaw.(*gpt.Table)
	if !ok {
		return fmt.Errorf("unsupported partition table type, only GPT is supported")
	}
	// plan what changes we will make
	resizes, err := planResizes(d, table, diskPartitionData, growPartitions, shrinkPartition)
	if err != nil {
		return err
	}
	if dryRun {
		log.Printf("Dry run specified, not performing resizes %+v", resizes)
		return nil
	}
	// integrity-check the source filesystems before anything destructive, so a
	// corrupt source aborts the resize rather than being shrunk in place or
	// copied into a new partition
	if err := checkSourceFilesystems(d, resizes, fixErrors); err != nil {
		return err
	}
	log.Printf("Will perform resizes %+v", resizes)
	return resize(d, resizes, fixErrors, preserveNumbers)
}
