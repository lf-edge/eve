package partitionresizer

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/disk"
	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/partition/gpt"
	"github.com/diskfs/go-diskfs/sync"
)

// ErrRebootToApply signals that a new partition table was committed to disk but
// the kernel could not re-read it live because the disk is busy (we are
// repartitioning the disk we booted from). The caller should reboot; the next
// boot's partition scan picks up the committed table. Detect with errors.Is.
var ErrRebootToApply = errors.New("partition table committed to disk; reboot required to apply")

// isUnknownFilesystem reports whether err is a *disk.UnknownFilesystemError.
// Use errors.As so the per-instance partition field doesn't matter
// (which it would with errors.Is against a zero-valued instance).
func isUnknownFilesystem(err error) bool {
	var u *disk.UnknownFilesystemError
	return errors.As(err, &u)
}

// resize performs the actual resize operations on the given disk.
// When preserveNumbers is set, a relocated partition is renumbered back to its
// original partition number after the copy, so that consumers referencing a
// partition by number (e.g. boot loaders) continue to find it.
func resize(d *disk.Disk, resizes []partitionResizeTarget, fixErrors, preserveNumbers bool) error {
	// do any shrinks first
	// this is idempotent. If I have a 500MB partition with a 500MB filesystem,
	// and shrink it to 400MB. If I stop, and then run it again, it will just say
	// it already is 400MB and move on.
	if err := shrinkFilesystems(d, resizes, fixErrors); err != nil {
		return err
	}
	// next shrink partitions
	// This is idempotent as well. I tell the GPT partition table what size
	// I want, and it will just set it again if it's already that size.
	if err := shrinkPartitions(d, resizes); err != nil {
		return err
	}

	// next create new partitions
	// It is important that they have different UUID, Type GUID, and predictable
	// but different names, so that we can identify them later for copying data.
	// Should it stop and then reboot, we want the original partitions to still be there.
	// They should have their original UUID and Label, so there is no conflict.
	// We also want the new partitions to have unique Type GUIDs and Names,
	// in case something relies on that to boot. For example, EFI System Partition.
	if err := createPartitions(d, resizes); err != nil {
		return err
	}

	// next copy filesystems
	// After the copy is done, verify the contents.
	if err := copyFilesystems(d, resizes); err != nil {
		return err
	}

	// finalize: in a single idempotent step, give each relocated target the
	// original partition's identity (name, type GUID, partition GUID,
	// attributes), set its partition number (the original number when
	// preserveNumbers, otherwise the number it was created with), and remove the
	// superseded original partition.
	if err := updatePartitions(d, resizes, preserveNumbers); err != nil {
		return err
	}

	return nil
}

// updatePartitions performs the final, idempotent phase of a resize. For each
// relocated partition it gives the target the identity of its original (name,
// type GUID, partition GUID, attributes), assigns the target's partition number
// (the original number when preserveNumbers, otherwise the number it was created
// with), and removes the now-superseded original -- all in a single partition
// table write.
//
// It supersedes the swapPartitions + removePartitions/removeAndRenumberPartitions
// sequence (still defined below but no longer called). Unlike the swap, it is idempotent:
// it identifies partitions by their on-disk start offset -- the one identifier
// that is stable across this phase, since names and numbers change -- sets the
// desired final state directly rather than exchanging values, and treats an
// already-removed original as a no-op. Re-running after an interruption
// therefore converges instead of undoing a completed operation.
func updatePartitions(d *disk.Disk, resizes []partitionResizeTarget, preserveNumbers bool) error {
	tableRaw, err := d.GetPartitionTable()
	if err != nil {
		return err
	}
	table, ok := tableRaw.(*gpt.Table)
	if !ok {
		return fmt.Errorf("unsupported partition table type, only GPT is supported")
	}
	// Index active partitions by start sector. Start is the only identifier that
	// does not change during this phase (names and numbers do), so it is the
	// stable key for locating the target and the original on a re-run.
	byStart := make(map[uint64]*gpt.Partition)
	for _, p := range table.Partitions {
		if p.Type == gpt.Unused {
			continue
		}
		byStart[p.Start] = p
	}
	sectorSize := int64(table.LogicalSectorSize)
	removeStart := make(map[uint64]bool)
	for _, r := range resizes {
		if r.create {
			// created partitions are appended below, not relocated from an original
			continue
		}
		if r.original.start == r.target.start {
			// shrunk in place: not relocated, so no identity move or removal
			continue
		}
		targetStart := uint64(r.target.start / sectorSize)
		originalStart := uint64(r.original.start / sectorSize)
		target := byStart[targetStart]
		if target == nil {
			return fmt.Errorf("target partition for %s at start %d not found", r.original.label, r.target.start)
		}
		// Copy the original's identity onto the target, but only while the
		// original is still present. Once a prior (interrupted) run has removed
		// it, the target already carries the final identity and this is skipped.
		if original := byStart[originalStart]; original != nil {
			log.Printf("finalizing partition at start %d to identity of %s (partition %d); removing original", r.target.start, r.original.label, r.original.number)
			target.Name = original.Name
			target.Type = original.Type
			target.GUID = original.GUID
			target.Attributes = original.Attributes
			removeStart[originalStart] = true
		}
		if preserveNumbers {
			target.Index = r.original.number
		}
	}
	if len(removeStart) > 0 {
		kept := make([]*gpt.Partition, 0, len(table.Partitions))
		for _, p := range table.Partitions {
			if p.Type != gpt.Unused && removeStart[p.Start] {
				continue
			}
			kept = append(kept, p)
		}
		table.Partitions = kept
	}
	// Publish any created partitions (e.g. the reserved ESP-B) in this same
	// final write, so a create never appears in the GPT before its filesystem
	// has been laid down. Skip one already present at its GUID (a completed
	// prior run), keeping the write idempotent.
	for _, r := range resizes {
		if !r.create {
			continue
		}
		already := false
		for _, p := range table.Partitions {
			if p.Type != gpt.Unused && p.GUID == r.target.uuid {
				already = true
				break
			}
		}
		if already {
			continue
		}
		log.Printf("publishing created partition %d %q (GUID %s) at start %d size %d", r.target.number, r.target.label, r.target.uuid, r.target.start, r.target.size)
		table.Partitions = append(table.Partitions, &gpt.Partition{
			Start: uint64(r.target.start / sectorSize),
			Size:  uint64(r.target.size),
			Type:  gpt.Type(r.target.typeGUID),
			Name:  r.target.label,
			GUID:  r.target.uuid,
			Index: r.target.number,
		})
	}
	if err := d.Partition(table); err != nil {
		if errors.Is(err, disk.ErrReReadDeferred) {
			return ErrRebootToApply
		}
		return fmt.Errorf("failed to write updated partition table: %v", err)
	}
	return nil
}

// createEmptyFilesystem lays down an empty filesystem for a create target in its
// allocated region, without publishing a GPT entry. The partition has no number
// yet (its entry is written only by the final updatePartitions), so the
// filesystem is built in a temp file sized to the region and copied to the
// region's byte offset -- the same mechanism the installer uses for the reserved
// ESP. FSNone leaves the region untouched.
func createEmptyFilesystem(d *disk.Disk, r partitionResizeTarget) error {
	if r.fsType == FSNone {
		return nil
	}
	var fsType filesystem.Type
	switch r.fsType {
	case FSFAT32:
		fsType = filesystem.TypeFat32
	case FSExt4:
		fsType = filesystem.TypeExt4
	default:
		return fmt.Errorf("unsupported create filesystem type %v", r.fsType)
	}
	device := d.Backend.Path()
	if device == "" {
		return fmt.Errorf("disk backend has no path")
	}
	tmpDir, err := os.MkdirTemp("", "createfs")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	tmpName := filepath.Join(tmpDir, "fs.img")
	tmpDisk, err := diskfs.Create(tmpName, r.target.size, diskfs.SectorSize512)
	if err != nil {
		return fmt.Errorf("create temp disk: %w", err)
	}
	if _, err := tmpDisk.CreateFilesystem(disk.FilesystemSpec{Partition: 0, FSType: fsType, VolumeLabel: r.target.label}); err != nil {
		_ = tmpDisk.Close()
		return fmt.Errorf("create %v: %w", fsType, err)
	}
	_ = tmpDisk.Close()
	log.Printf("laying down empty %v for %q at start %d size %d", fsType, r.target.label, r.target.start, r.target.size)
	return CopyRange(tmpName, device, 0, r.target.start, r.target.size, 0)
}

// createPartitions creates new partitions as per the resize targets, taking
// all of the characteristics from the original partitions except for start/end/size.
func createPartitions(d *disk.Disk, resizes []partitionResizeTarget) error {
	// first create the new partitions in the partition table and write it
	tableRaw, err := d.GetPartitionTable()
	if err != nil {
		return err
	}
	table, ok := tableRaw.(*gpt.Table)
	if !ok {
		return fmt.Errorf("unsupported partition table type, only GPT is supported")
	}
	partitions := table.Partitions
	indexMap := map[int]*gpt.Partition{}
	for _, p := range partitions {
		indexMap[p.Index] = p
	}
	labelMap := map[string]bool{}
	for _, p := range partitions {
		labelMap[p.Name] = true
	}
	for _, r := range resizes {
		if r.create {
			// A create has no interim relocated partition; its GPT entry is
			// published only by the final updatePartitions write.
			continue
		}
		// no change in start, just copy over, it already was handled
		if r.original.start == r.target.start {
			log.Printf("partition %d %s: no location change, no need to create additional partition", r.original.number, r.original.label)
			continue
		}
		log.Printf("creating new partition %s: original %+v, target %+v", r.original.label, r.original, r.target)
		// get existing partition info
		p, ok := indexMap[r.original.number]
		if !ok {
			return fmt.Errorf("original partition %d not found in partition table", r.original.number)
		}
		altName := getAlternateLabel(p.Name)
		// see if it already exists
		if labelMap[altName] {
			log.Printf("alternate partition name %s already exists, assuming partition was already created", altName)
			continue
		}
		// create the new partition
		newPart := gpt.Partition{
			Start:      uint64(r.target.start / int64(table.LogicalSectorSize)),
			Size:       uint64(r.target.size),
			Type:       gpt.LinuxFilesystem, // set to Linux Filesystem type to avoid conflicts
			Name:       altName,
			Attributes: p.Attributes,
			Index:      r.target.number,
			// explicitly leave GUID blank so it autogenerates a new one
		}
		partitions = append(partitions, &newPart)
	}
	// write the updated partition table; we rely on the GPT implementation to sort out the ordering
	table.Partitions = partitions
	if err := d.Partition(table); err != nil {
		if errors.Is(err, disk.ErrReReadDeferred) {
			return ErrRebootToApply
		}
		return fmt.Errorf("failed to write updated partition table: %v", err)
	}
	return nil
}

func copyFilesystems(d *disk.Disk, resizes []partitionResizeTarget) error {
	// it depends on the filesystem type:
	// - squashfs, ext4, unknown: raw data copy
	// - fat32: use filesystem copy
	for _, r := range resizes {
		if r.create {
			// No source to copy: lay down an empty filesystem in the allocated
			// region by offset, without publishing a GPT entry (that happens in
			// the final write).
			if err := createEmptyFilesystem(d, r); err != nil {
				return fmt.Errorf("failed to create filesystem for new partition %q: %v", r.target.label, err)
			}
			continue
		}
		if r.original.start == r.target.start {
			log.Printf("partition %d %s: no location change, no need to copy filesystem", r.original.number, r.original.label)
			continue
		}
		log.Printf("copying data from original partition %d to new partition %d", r.original.number, r.target.number)
		fs, err := d.GetFilesystem(r.original.number)
		switch {
		case err != nil && !isUnknownFilesystem(err):
			return fmt.Errorf("failed to get filesystem for partition %s: %v", r.original.label, err)
		case err != nil || fs.Type() == filesystem.TypeSquashfs:
			log.Printf("partition %d -> %d: performing raw data copy", r.original.number, r.target.number)
			if err := sync.CopyPartitionRaw(d, r.original.number, r.target.number); err != nil {
				return fmt.Errorf("failed to copy raw data for partition %s: %v", r.original.label, err)
			}
		case fs.Type() == filesystem.TypeExt4:
			// On resume, the target may already hold a complete, matching copy
			// from a prior run; in that case skip the reformat+recopy. CompareFS
			// is a structural/content equality check against the source, not a
			// filesystem integrity check.
			if existing, eerr := d.GetFilesystem(r.target.number); eerr == nil && sync.CompareFS(fs, existing) == nil {
				log.Printf("partition %d -> %d: target filesystem already matches source, skipping copy", r.original.number, r.target.number)
				continue
			}
			newFS, err := d.CreateFilesystem(disk.FilesystemSpec{
				Partition:   r.target.number,
				FSType:      filesystem.TypeExt4,
				VolumeLabel: fs.Label(),
			})
			if err != nil {
				return fmt.Errorf("failed to create ext4 filesystem for new partition %s: %v", r.original.label, err)
			}
			// use filesystem copy
			if err := sync.CopyFileSystem(fs, newFS); err != nil {
				return fmt.Errorf("failed to copy ext4 filesystem data for partition %s: %v", r.original.label, err)
			}
			if err := sync.CompareFS(fs, newFS); err != nil {
				return fmt.Errorf("verification failed for partition %s: %v", r.original.label, err)
			}
			log.Printf("partition %d -> %d: filesystem %v copy verified", r.original.number, r.target.number, fs.Type())
		case fs.Type() == filesystem.TypeFat32:
			// create a new filesystem on the new partition
			newFS, err := d.CreateFilesystem(disk.FilesystemSpec{
				Partition:   r.target.number,
				FSType:      filesystem.TypeFat32,
				VolumeLabel: fs.Label(),
			})
			if err != nil {
				return fmt.Errorf("failed to create FAT32 filesystem for new partition %s: %v", r.original.label, err)
			}
			// use filesystem copy
			if err := sync.CopyFileSystem(fs, newFS); err != nil {
				return fmt.Errorf("failed to copy FAT32 filesystem data for partition %s: %v", r.original.label, err)
			}
			log.Printf("partition %d -> %d: filesystem %v copied file content", r.original.number, r.target.number, fs.Type())
			if err := sync.CompareFS(fs, newFS); err != nil {
				return fmt.Errorf("verification failed for partition %s: %v", r.original.label, err)
			}
			log.Printf("partition %d -> %d: filesystem %v copy verified", r.original.number, r.target.number, fs.Type())
		default:
			return fmt.Errorf("unsupported filesystem type %v for partition %s", fs.Type(), r.original.label)
		}

	}
	return nil
}

// remove partitions removes the original partitions after data has been copied
func removePartitions(d *disk.Disk, resizes []partitionResizeTarget) error {
	// first create the new partitions in the partition table and write it
	tableRaw, err := d.GetPartitionTable()
	if err != nil {
		return err
	}
	table, ok := tableRaw.(*gpt.Table)
	if !ok {
		return fmt.Errorf("unsupported partition table type, only GPT is supported")
	}
	toRemove := make(map[int]bool)
	for _, r := range resizes {
		if r.original.number == r.target.number {
			log.Printf("partition %d %s: no change in partition number, no need to remove old partition", r.original.number, r.original.label)
			continue
		}
		log.Printf("removing old partition %d", r.original.number)
		// mark this partition for removal
		toRemove[r.original.number] = true
	}
	// remove any marked for removal
	for _, p := range table.Partitions {
		if toRemove[p.Index] {
			log.Printf("removing partition %d from partition table", p.Index)
			p.Type = gpt.Unused
		}
	}
	// write the updated partition table
	if err := d.Partition(table); err != nil {
		if errors.Is(err, disk.ErrReReadDeferred) {
			return ErrRebootToApply
		}
		return fmt.Errorf("failed to write updated partition table: %v", err)
	}
	return nil
}

// removeAndRenumberPartitions removes the original partitions and reassigns each
// relocated target partition's GPT slot index to the original partition's number, so
// the resized partition keeps the same partition number it had before. This is the
// preserve-numbers counterpart to removePartitions, and must run after the data
// has been copied and the identities swapped onto the target partitions. Removal and
// renumbering are done in a single GPT table write so the device never persists an
// intermediate state where the original numbers are gone but the relocated slots have
// not yet been renumbered.
//
// The renumbered entry stays at its new on-disk offset, so the resulting GPT entries
// end up out of disk-offset order. That is permitted by the GPT specification and is
// invisible to consumers that locate a partition by its number (e.g. a boot loader
// referencing (hd0,gptN)); no common tool treats it as an error, though some offer an
// optional manual sort to restore offset order.
func removeAndRenumberPartitions(d *disk.Disk, resizes []partitionResizeTarget) error {
	tableRaw, err := d.GetPartitionTable()
	if err != nil {
		return err
	}
	table, ok := tableRaw.(*gpt.Table)
	if !ok {
		return fmt.Errorf("unsupported partition table type, only GPT is supported")
	}
	// map partition number -> position in the slice, captured before any mutation so
	// that the lookups below are unaffected by the index reassignments we make.
	indexToPosition := make(map[int]int)
	for i, p := range table.Partitions {
		indexToPosition[p.Index] = i
	}
	// slice positions of the original partitions to drop, keyed by position rather
	// than partition number: once we reassign a target's Index to the original number,
	// keying removal on Index would also match (and wrongly drop) the renumbered target.
	removePositions := make(map[int]bool)
	for _, r := range resizes {
		if r.original.number == r.target.number {
			log.Printf("partition %d %s: no change in partition number, no need to renumber", r.original.number, r.original.label)
			continue
		}
		origPos, ok := indexToPosition[r.original.number]
		if !ok {
			return fmt.Errorf("original partition %d not found in partition table", r.original.number)
		}
		targetPos, ok := indexToPosition[r.target.number]
		if !ok {
			return fmt.Errorf("target partition %d not found in partition table", r.target.number)
		}
		log.Printf("renumbering partition %d -> %d (label %s) and removing original slot", r.target.number, r.original.number, r.original.label)
		table.Partitions[targetPos].Index = r.original.number
		removePositions[origPos] = true
	}
	// rebuild the slice, dropping the vacated original slots so their numbers are free
	partitions := make([]*gpt.Partition, 0, len(table.Partitions))
	for i, p := range table.Partitions {
		if removePositions[i] {
			continue
		}
		partitions = append(partitions, p)
	}
	table.Partitions = partitions
	if err := d.Partition(table); err != nil {
		if errors.Is(err, disk.ErrReReadDeferred) {
			return ErrRebootToApply
		}
		return fmt.Errorf("failed to write renumbered partition table: %v", err)
	}
	return nil
}

// swapPartitions swaps the labels, Type GUIDs, and UUIDs of the original and target partitions,
// as well as any attributes flags.
func swapPartitions(d *disk.Disk, resizes []partitionResizeTarget) error {
	// first create the new partitions in the partition table and write it
	tableRaw, err := d.GetPartitionTable()
	if err != nil {
		return err
	}
	table, ok := tableRaw.(*gpt.Table)
	if !ok {
		return fmt.Errorf("unsupported partition table type, only GPT is supported")
	}
	indexToPosition := make(map[int]int)
	for i, p := range table.Partitions {
		indexToPosition[p.Index] = i
	}
	for _, r := range resizes {
		if r.original.number == r.target.number {
			log.Printf("partition %d %s: no change in partition number, no need to swap partitions", r.original.number, r.original.label)
			continue
		}
		log.Printf("swapping values on partitions original %d -> %d ", r.original.number, r.target.number)
		// mark this partition for removal
		original := table.Partitions[indexToPosition[r.original.number]]
		target := table.Partitions[indexToPosition[r.target.number]]
		originalName := original.Name
		originalType := original.Type
		originalGUID := original.GUID
		originalAttributes := original.Attributes

		// swap values
		original.Name = target.Name
		original.Type = target.Type
		original.GUID = target.GUID
		original.Attributes = target.Attributes

		target.Name = originalName
		target.Type = originalType
		target.GUID = originalGUID
		target.Attributes = originalAttributes
	}
	// write the updated partition table
	if err := d.Partition(table); err != nil {
		if errors.Is(err, disk.ErrReReadDeferred) {
			return ErrRebootToApply
		}
		return fmt.Errorf("failed to write updated partition table: %v", err)
	}
	return nil
}

// checkSourceFilesystems integrity-checks every source filesystem the resize
// will read or modify, before any destructive step runs. ext4 sources are
// checked with e2fsck and fat32 sources with fsck.fat; by default the checks
// are read-only and an inconsistent filesystem aborts the resize, while
// fixErrors upgrades them to repair. squashfs and other types have no
// applicable checker and are copied as-is, so a corrupt squashfs source is
// reproduced faithfully. This makes the integrity guarantee symmetric across
// the shrink source and the grow sources, rather than only checking the shrink
// partition that resize2fs would have checked anyway.
func checkSourceFilesystems(d *disk.Disk, resizes []partitionResizeTarget, fixErrors bool) error {
	device := d.Backend.Path()
	if device == "" {
		return fmt.Errorf("cannot check source filesystems: disk backend has no path")
	}
	checked := map[int]bool{}
	for _, r := range resizes {
		if r.create {
			continue // no source filesystem to check
		}
		if checked[r.original.number] {
			continue
		}
		checked[r.original.number] = true
		fs, err := d.GetFilesystem(r.original.number)
		if err != nil {
			if isUnknownFilesystem(err) {
				// no recognized filesystem (e.g. squashfs on a 512-byte
				// sector disk, or raw data) -- nothing we can check
				log.Printf("partition %d: no recognized filesystem, skipping integrity check", r.original.number)
				continue
			}
			return fmt.Errorf("failed to get filesystem for source partition %d: %w", r.original.number, err)
		}
		var fsck func(string, bool) error
		switch fs.Type() {
		case filesystem.TypeExt4:
			fsck = execE2fsck
		case filesystem.TypeFat32:
			fsck = execFsckFat
		default:
			// squashfs and other types have no applicable integrity check
			log.Printf("partition %d: filesystem type %v has no integrity check, skipping", r.original.number, fs.Type())
			continue
		}
		log.Printf("checking source filesystem on partition %d (%v)", r.original.number, fs.Type())
		if err := checkFilesystem(device, r.original, fsck, fixErrors); err != nil {
			return fmt.Errorf("integrity check failed for source partition %d: %w", r.original.number, err)
		}
	}
	return nil
}

func shrinkFilesystems(d *disk.Disk, resizes []partitionResizeTarget, fixErrors bool) error {
	for _, r := range resizes {
		if r.original.size <= r.target.size {
			log.Printf("filesystem on partition %d does not require shrinking, skipping", r.original.number)
			continue
		}
		log.Printf("shrinking filesystem on partition %d label '%s' from %d to %d bytes / %d to %d MB", r.original.number, r.original.label, r.original.size, r.target.size, r.original.size/MB, r.target.size/MB)
		// verify ext4 fs on shrink partition
		fs, err := d.GetFilesystem(r.original.number)
		if err != nil {
			return fmt.Errorf("failed to get filesystem for shrink partition: %v", err)
		}
		if fs.Type() != filesystem.TypeExt4 {
			return fmt.Errorf("unsupported filesystem type for shrinking: %v", fs.Type())
		}

		// perform the shrink
		// note that resize will leave it alone if it already is the desired size
		p := d.Backend.Path()
		if p == "" {
			return fmt.Errorf("cannot shrink filesystem: disk backend has no path")
		}
		delta := r.target.size - r.original.size
		if err := resizeFilesystem(p, r.original, delta, fixErrors); err != nil {
			return err
		}
	}
	return nil
}

func shrinkPartitions(d *disk.Disk, resizes []partitionResizeTarget) error {
	table, ok := d.Table.(*gpt.Table)
	var resizeCount int
	if !ok {
		return fmt.Errorf("unsupported partition table type, only GPT is supported")
	}
	// Look up partitions by their GPT Index, not by slice position.
	// table.Partitions is compacted (only active entries), so the old
	// table.Partitions[number-1] assumed a contiguous 1..N numbering and
	// indexed the wrong entry -- or panicked -- on any non-contiguous layout
	// (e.g. EVE's persist partition at index 9).
	byIndex := make(map[int]*gpt.Partition)
	for _, p := range table.Partitions {
		byIndex[p.Index] = p
	}
	for _, r := range resizes {
		if r.original.size <= r.target.size {
			log.Printf("partition %d does not require shrinking, skipping", r.original.number)
			continue
		}
		p, ok := byIndex[r.original.number]
		if !ok {
			return fmt.Errorf("partition %d not found in partition table", r.original.number)
		}
		log.Printf("Resizing partition %d to %d bytes", r.original.number, r.target.size)
		// set the new desired size; set End to 0 so it is recalculated
		p.Size = uint64(r.target.size)
		p.End = 0
		resizeCount++
	}
	if resizeCount == 0 {
		return nil
	}
	if err := d.Partition(table); err != nil {
		if errors.Is(err, disk.ErrReReadDeferred) {
			return ErrRebootToApply
		}
		return fmt.Errorf("failed to write partition table after shrinking: %v", err)
	}
	return nil
}
