package partitionresizer

import (
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/disk"
	"github.com/diskfs/go-diskfs/partition/gpt"
)

// Apply reconciles the disk so that every PartitionSpec in desired exists with
// its declared identity and at least MinSize bytes, optionally shrinking one
// partition (shrink) to free space.
//
// desired is monotonically non-destructive: a partition that is absent is
// created (and, per its FS, formatted empty), one smaller than MinSize is grown
// in place-preserving fashion, and one already at least MinSize is left
// untouched -- it is never shrunk. shrink is the ONLY operation that reduces a
// partition; when nil, nothing can be shrunk, so a grow+create-only call cannot
// shrink anything by accident.
//
// An existing partition is located either by GUID (the default) or, when a spec
// sets Match, by name/label/uuid; a matched partition's type and label are
// asserted against the spec so Apply never operates on an unexpected disk.
// diskPath may be empty, in which case the disk is discovered by the Match and
// shrink identifiers (all of which must resolve to the same disk).
//
// A created partition's GPT entry is published only by the final table write, so
// an interrupted run is recovered by re-running: a partition present at its GUID
// is complete (filesystem included), otherwise it is (re)made.
func Apply(diskPath string, desired []PartitionSpec, shrink *ShrinkSpec, fixErrors, dryRun bool) error {
	diskPath, desired, shrink, err := resolveDiskAndNames(diskPath, desired, shrink, "")
	if err != nil {
		return err
	}

	// Open the whole disk read-write but NOT O_EXCL: partitionresizer shells out
	// to e2fsck/resize2fs/fsck.fat on the child partitions, which open those
	// O_EXCL; holding the parent O_EXCL would make those child opens fail on a
	// real block device. The caller guarantees the partitions are unmounted.
	backendFile, err := file.OpenFromPathWithExclusive(diskPath, false, false)
	if err != nil {
		return err
	}
	d, err := diskfs.OpenBackend(maybeWrapBackend(backendFile))
	if err != nil {
		return err
	}
	tableRaw, err := d.GetPartitionTable()
	if err != nil {
		return err
	}
	table, ok := tableRaw.(*gpt.Table)
	if !ok {
		return fmt.Errorf("unsupported partition table type, only GPT is supported")
	}

	resizes, err := planApply(d, table, desired, shrink)
	if err != nil {
		return err
	}
	if len(resizes) == 0 {
		log.Printf("Apply: disk already matches desired state, nothing to do")
		return nil
	}

	if dryRun {
		for _, r := range resizes {
			switch {
			case r.create:
				log.Printf("Apply plan: create %q (GUID %s) partition %d size %d fs %v", r.target.label, r.target.uuid, r.target.number, r.target.size, r.fsType)
			case r.target.size < r.original.size:
				log.Printf("Apply plan: shrink %q (partition %d) %d -> %d", r.original.label, r.original.number, r.original.size, r.target.size)
			default:
				log.Printf("Apply plan: grow %q (partition %d) %d -> %d", r.original.label, r.original.number, r.original.size, r.target.size)
			}
		}
		return nil
	}
	if err := checkSourceFilesystems(d, resizes, fixErrors); err != nil {
		return err
	}
	return resize(d, resizes, fixErrors, true)
}

// planApply diffs desired + shrink against the live GPT and returns the full,
// allocated resize plan. It grows/creates the desired partitions and, when a
// shrink is given, frees space by reducing that partition: to an explicit Size,
// or -- when Size is 0 -- only as much as the grows/creates need (shrink-to-fit),
// rounded up to a whole GB. Resumed grows (whose relocated "<label>_resized2"
// partition already exists) are carried through unallocated.
func planApply(d *disk.Disk, table *gpt.Table, desired []PartitionSpec, shrink *ShrinkSpec) ([]partitionResizeTarget, error) {
	grows, creates, err := planPartitionSpecs(table, desired)
	if err != nil {
		return nil, err
	}

	var shrinkData *partitionData
	shrinkToFit := false
	var shrinkSize int64
	if shrink != nil {
		sd, err := matchTableIdentifier(table, shrink.ID)
		if err != nil {
			return nil, err
		}
		shrinkData = &sd
		shrinkSize = shrink.Size
		shrinkToFit = shrink.Size == 0
	}

	doneGrows, pendingGrows := splitResumedGrows(table, grows)

	// build assembles the allocation input. The shrink, when present, must come
	// first so calculateResizes frees its tail space before placing the grows and
	// creates.
	build := func(shrinkTarget *partitionResizeTarget) []partitionResizeTarget {
		var out []partitionResizeTarget
		if shrinkTarget != nil {
			out = append(out, *shrinkTarget)
		}
		out = append(out, pendingGrows...)
		out = append(out, creates...)
		return out
	}
	mkShrink := func(targetSize int64) partitionResizeTarget {
		tgt := *shrinkData
		tgt.size = targetSize
		tgt.start = shrinkData.start // shrink in place
		tgt.end = shrinkData.start + targetSize - 1
		return partitionResizeTarget{original: *shrinkData, target: tgt}
	}

	// Explicit-size shrink: reduce to that size (when currently larger) in a
	// single allocation pass together with the grows and creates.
	if shrinkData != nil && !shrinkToFit {
		var st *partitionResizeTarget
		if shrinkData.size > shrinkSize {
			s := mkShrink(shrinkSize)
			st = &s
		}
		resizes, err := calculateResizes(d.Size, table.Partitions, build(st))
		if err != nil {
			return nil, err
		}
		return append(doneGrows, resizes...), nil
	}

	// No shrink, or shrink-to-fit: first try to place the grows and creates
	// without shrinking anything.
	resizes, err := calculateResizes(d.Size, table.Partitions, build(nil))
	if err == nil {
		return append(doneGrows, resizes...), nil
	}
	var spaceErr *InsufficientSpaceError
	if !errors.As(err, &spaceErr) {
		return nil, err
	}
	if shrinkData == nil {
		return nil, fmt.Errorf("insufficient space to grow/create the requested partitions, and no shrink partition specified")
	}

	// shrink-to-fit: free the total requested size (rounded up to a whole GB).
	var totalGrow int64
	for _, g := range pendingGrows {
		totalGrow += g.target.size
	}
	for _, c := range creates {
		totalGrow += c.target.size
	}
	if totalGrow%GB != 0 {
		totalGrow = ((totalGrow / GB) + 1) * GB
	}
	if totalGrow >= shrinkData.size {
		return nil, fmt.Errorf("cannot shrink %q by %d bytes to free space: only %d bytes available", shrinkData.label, totalGrow, shrinkData.size)
	}
	s := mkShrink(shrinkData.size - totalGrow)
	resizes, err = calculateResizes(d.Size, table.Partitions, build(&s))
	if err != nil {
		return nil, err
	}
	return append(doneGrows, resizes...), nil
}

// planPartitionSpecs diffs desired against the live GPT and returns the grow and
// create targets (no shrink). A spec with Match locates an existing partition by
// name/label/uuid and must exist. A spec without Match is keyed by GUID: absent
// -> create; present -> grow (relocate+copy, number preserved) when smaller than
// MinSize, or no-op when already at least MinSize (never shrunk). A matched
// partition's type and label, when set, are asserted.
func planPartitionSpecs(table *gpt.Table, desired []PartitionSpec) (grows, creates []partitionResizeTarget, err error) {
	byGUID := make(map[string]*gpt.Partition)
	usedNumbers := make(map[int]bool)
	for _, p := range table.Partitions {
		if p.Type == gpt.Unused {
			continue
		}
		byGUID[strings.ToUpper(p.GUID)] = p
		usedNumbers[p.Index] = true
	}

	for _, spec := range desired {
		// Identifier-based match locates an existing partition to grow; it must
		// exist (creation is expressed by GUID, below).
		if spec.Match != nil {
			pd, err := matchTableIdentifier(table, spec.Match)
			if err != nil {
				return nil, nil, fmt.Errorf("grow target %s=%s: %w", spec.Match.By(), spec.Match.Value(), err)
			}
			if err := assertSpecIdentity(spec, pd.typeGUID, pd.label, pd.uuid); err != nil {
				return nil, nil, err
			}
			if pd.size >= spec.MinSize {
				continue // already large enough; never shrink via desired
			}
			tgt := pd
			tgt.size = spec.MinSize
			grows = append(grows, partitionResizeTarget{original: pd, target: tgt})
			continue
		}

		guid := strings.ToUpper(spec.GUID)
		p := byGUID[guid]
		if p == nil {
			// No partition with this GUID: create it.
			if spec.Index != 0 && usedNumbers[spec.Index] {
				return nil, nil, fmt.Errorf("cannot create %q at partition %d: slot occupied by a different GUID", spec.Label, spec.Index)
			}
			creates = append(creates, partitionResizeTarget{
				create: true,
				fsType: spec.FS,
				target: partitionData{
					label:    spec.Label,
					uuid:     guid,
					typeGUID: spec.TypeGUID,
					number:   spec.Index,
					size:     spec.MinSize,
				},
			})
			continue
		}
		if err := assertSpecIdentity(spec, string(p.Type), p.Name, guid); err != nil {
			return nil, nil, err
		}
		if p.GetSize() >= spec.MinSize {
			// Already at least MinSize: never shrink. A requested index change on
			// an otherwise-satisfied partition (metadata-only renumber) is not yet
			// implemented; flag it rather than silently ignoring it.
			if spec.Index != 0 && p.Index != spec.Index {
				return nil, nil, fmt.Errorf("partition %q is already sized but has number %d, not requested %d (metadata-only renumber unimplemented)", spec.Label, p.Index, spec.Index)
			}
			continue
		}
		// Grow: relocate + copy, preserving the partition number.
		orig := gptToData(p)
		tgt := orig
		tgt.size = spec.MinSize
		grows = append(grows, partitionResizeTarget{original: orig, target: tgt})
	}
	return grows, creates, nil
}

// assertSpecIdentity verifies that a matched partition's type and label agree
// with the spec, so a resize never touches an unexpected disk. Empty spec fields
// are not asserted.
func assertSpecIdentity(spec PartitionSpec, gotType, gotLabel, guid string) error {
	if spec.TypeGUID != "" && !strings.EqualFold(gotType, spec.TypeGUID) {
		return fmt.Errorf("partition %q (GUID %s): type %s does not match expected %s", spec.Label, guid, gotType, spec.TypeGUID)
	}
	if spec.Label != "" && gotLabel != spec.Label {
		return fmt.Errorf("partition GUID %s: label %q does not match expected %q", guid, gotLabel, spec.Label)
	}
	return nil
}

// resolveDiskAndNames selects the target disk and normalizes identifiers before
// the disk is opened. When diskPath is empty the disk is discovered from the
// must-exist identifiers (Match grows and the shrink), which must all resolve to
// exactly one disk. Any by-name identifier (a kernel device name like sda3,
// which the GPT does not carry) is then rewritten to the partition's UUID via
// sysfs, so all subsequent matching is uuid/label against the live GPT. syspath
// overrides the sysfs root ("" => /sys); it exists so the discovery and by-name
// paths can be tested against a synthetic tree.
func resolveDiskAndNames(diskPath string, desired []PartitionSpec, shrink *ShrinkSpec, syspath string) (string, []PartitionSpec, *ShrinkSpec, error) {
	if diskPath == "" {
		must := mustExistIdentifiers(desired, shrink)
		if len(must) == 0 {
			return "", nil, nil, fmt.Errorf("Apply requires a disk, or at least one match/shrink identifier to discover one")
		}
		disks, err := findDisks("", syspath)
		if err != nil {
			return "", nil, nil, fmt.Errorf("discover disks: %w", err)
		}
		matched, err := filterDisksByPartitions(disks, must)
		if err != nil {
			return "", nil, nil, err
		}
		switch len(matched) {
		case 0:
			return "", nil, nil, fmt.Errorf("no disk found matching the given identifiers")
		case 1:
			diskPath = "/dev/" + matched[0]
		default:
			return "", nil, nil, fmt.Errorf("multiple disks match the given identifiers: %v", matched)
		}
		log.Printf("Apply: discovered disk %s", diskPath)
	}

	if anyNameIdentifier(desired, shrink) {
		disks, err := findDisks(diskPath, syspath)
		if err != nil {
			return "", nil, nil, fmt.Errorf("resolve partition names on %s: %w", diskPath, err)
		}
		desired, shrink, err = resolveNameIdentifiers(disks[filepath.Base(diskPath)], desired, shrink)
		if err != nil {
			return "", nil, nil, err
		}
	}
	return diskPath, desired, shrink, nil
}

// mustExistIdentifiers returns the identifiers that must already be present on
// the disk: every Match (grow) identifier and the shrink identifier. A create's
// GUID is deliberately excluded -- it does not exist yet -- so these are the
// identifiers usable to select a disk during auto-discovery.
func mustExistIdentifiers(desired []PartitionSpec, shrink *ShrinkSpec) []PartitionIdentifier {
	var ids []PartitionIdentifier
	for _, spec := range desired {
		if spec.Match != nil {
			ids = append(ids, spec.Match)
		}
	}
	if shrink != nil {
		ids = append(ids, shrink.ID)
	}
	return ids
}

// anyNameIdentifier reports whether any Match or shrink identifier selects a
// partition by kernel device name, which requires sysfs resolution.
func anyNameIdentifier(desired []PartitionSpec, shrink *ShrinkSpec) bool {
	for _, spec := range desired {
		if spec.Match != nil && spec.Match.By() == IdentifierByName {
			return true
		}
	}
	return shrink != nil && shrink.ID.By() == IdentifierByName
}

// resolveNameIdentifiers replaces every by-name Match/shrink identifier with the
// equivalent by-uuid identifier, looked up in the sysfs-discovered partition
// data. It returns copies so the caller's specs are not mutated; a name with no
// matching partition (or no discoverable UUID) is an error.
func resolveNameIdentifiers(parts []partitionData, desired []PartitionSpec, shrink *ShrinkSpec) ([]PartitionSpec, *ShrinkSpec, error) {
	byName := make(map[string]string) // kernel device name -> partition uuid
	for _, pd := range parts {
		if pd.name != "" {
			byName[pd.name] = pd.uuid
		}
	}
	resolve := func(id PartitionIdentifier) (PartitionIdentifier, error) {
		if id == nil || id.By() != IdentifierByName {
			return id, nil
		}
		uuid, ok := byName[id.Value()]
		if !ok {
			return nil, fmt.Errorf("partition name %q not found on disk", id.Value())
		}
		if uuid == "" {
			return nil, fmt.Errorf("partition %q has no discoverable UUID to match against the GPT", id.Value())
		}
		return NewPartitionIdentifier(IdentifierByUUID, uuid), nil
	}
	outDesired := make([]PartitionSpec, len(desired))
	copy(outDesired, desired)
	for i := range outDesired {
		m, err := resolve(outDesired[i].Match)
		if err != nil {
			return nil, nil, err
		}
		outDesired[i].Match = m
	}
	outShrink := shrink
	if shrink != nil {
		id, err := resolve(shrink.ID)
		if err != nil {
			return nil, nil, err
		}
		s := *shrink
		s.ID = id
		outShrink = &s
	}
	return outDesired, outShrink, nil
}

// splitResumedGrows separates grow targets whose relocated "<label>_resized2"
// partition already exists on disk -- from an interrupted run -- ("done", with
// the target set to that existing relocated geometry) from those still needing
// space allocated ("pending"). No-op grows (already at the target size) are
// dropped. Feeding a resumed grow back through calculateResizes would count its
// space as occupied and mis-plan (diskfs/partitionresizer#13), so it must be
// excluded. Only relocating grows belong here -- not creates or shrinks.
func splitResumedGrows(table *gpt.Table, grows []partitionResizeTarget) (done, pending []partitionResizeTarget) {
	existingByName := make(map[string]*gpt.Partition)
	for _, p := range table.Partitions {
		if p.Type == gpt.Unused {
			continue
		}
		existingByName[p.Name] = p
	}
	for _, pr := range grows {
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
	return done, pending
}

// gptToData converts a go-diskfs GPT partition to the internal partitionData.
func gptToData(p *gpt.Partition) partitionData {
	start := p.GetStart()
	size := p.GetSize()
	return partitionData{
		label:    p.Name,
		uuid:     p.UUID(),
		typeGUID: string(p.Type),
		number:   p.Index,
		start:    start,
		end:      start + size - 1,
		size:     size,
	}
}

// matchTableIdentifier resolves a PartitionIdentifier (label or uuid) against the
// live GPT. Name-based identification needs sysfs discovery and is not supported
// here.
func matchTableIdentifier(table *gpt.Table, id PartitionIdentifier) (partitionData, error) {
	for _, p := range table.Partitions {
		if p.Type == gpt.Unused {
			continue
		}
		var ok bool
		switch id.By() {
		case IdentifierByLabel:
			ok = p.Name == id.Value()
		case IdentifierByUUID:
			ok = strings.EqualFold(p.UUID(), id.Value())
		case IdentifierByName:
			return partitionData{}, fmt.Errorf("identifier by name is not supported here; use label or uuid")
		}
		if ok {
			return gptToData(p), nil
		}
	}
	return partitionData{}, fmt.Errorf("partition not found: %s=%s", id.By(), id.Value())
}
