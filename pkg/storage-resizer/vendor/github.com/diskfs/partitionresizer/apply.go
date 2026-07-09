package partitionresizer

import (
	"fmt"
	"log"
	"strings"

	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/partition/gpt"
)

// Apply reconciles the disk so that every PartitionSpec in desired exists with
// its declared identity and at least MinSize bytes, optionally shrinking one
// partition (shrink) to free space. It is the declarative counterpart to Run.
//
// desired is monotonically non-destructive: a partition that is absent is
// created (and, per its FS, formatted empty), one smaller than MinSize is grown
// in place-preserving fashion, and one already at least MinSize is left
// untouched -- it is never shrunk. shrink is the ONLY operation that reduces a
// partition; when nil, nothing can be shrunk, so a grow+create-only call cannot
// shrink anything by accident. Matching is by GUID, and a matched partition's
// type and label must equal the spec or Apply aborts, so it never operates on an
// unexpected disk.
//
// A created partition's GPT entry is published only by the final table write, so
// an interrupted run is recovered by re-running: a partition present at its GUID
// is complete (filesystem included), otherwise it is (re)made.
func Apply(diskPath string, desired []PartitionSpec, shrink *ShrinkSpec, fixErrors, dryRun bool) error {
	if diskPath == "" {
		return fmt.Errorf("Apply requires an explicit disk")
	}
	// Open the given disk directly and match specs against its live GPT. Unlike
	// Run, Apply does not filter candidate disks by "has all these partitions":
	// a create spec's GUID does not exist yet, so that filter could never match.
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

	targets, err := planSpecs(table, desired, shrink)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		log.Printf("Apply: disk already matches desired state, nothing to do")
		return nil
	}

	// Only relocating grows support resume via the "<label>_resized2" marker, so
	// only they go through the resume split; a resumed one bypasses allocation.
	// Creates (resume-safe by GUID) and the in-place shrink still need
	// calculateResizes to place them, so they join the pending grows.
	var grows, creates []partitionResizeTarget
	var shrinkT *partitionResizeTarget
	for _, t := range targets {
		switch {
		case t.create:
			creates = append(creates, t)
		case t.target.size < t.original.size:
			tt := t
			shrinkT = &tt
		default:
			grows = append(grows, t)
		}
	}
	doneGrows, pendingGrows := splitResumedGrows(table, grows)
	// Order matters in calculateResizes: the shrink frees tail space that the
	// grows and creates then allocate into, so it must come first.
	var toAllocate []partitionResizeTarget
	if shrinkT != nil {
		toAllocate = append(toAllocate, *shrinkT)
	}
	toAllocate = append(toAllocate, pendingGrows...)
	toAllocate = append(toAllocate, creates...)
	resizes, err := calculateResizes(d.Size, table.Partitions, toAllocate)
	if err != nil {
		return err
	}
	resizes = append(doneGrows, resizes...)

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

// planSpecs diffs desired + shrink against the live GPT and returns the resize
// targets. Absent -> create; size < MinSize -> grow (relocate+copy, number
// preserved); size >= MinSize with matching identity -> no-op; the shrink, if
// given and the partition is larger than its target, -> shrink in place.
func planSpecs(table *gpt.Table, desired []PartitionSpec, shrink *ShrinkSpec) ([]partitionResizeTarget, error) {
	byGUID := make(map[string]*gpt.Partition)
	usedNumbers := make(map[int]bool)
	for _, p := range table.Partitions {
		if p.Type == gpt.Unused {
			continue
		}
		byGUID[strings.ToUpper(p.GUID)] = p
		usedNumbers[p.Index] = true
	}

	var targets []partitionResizeTarget
	for _, spec := range desired {
		guid := strings.ToUpper(spec.GUID)
		p := byGUID[guid]
		if p == nil {
			// No partition with this GUID: create it.
			if spec.Index != 0 && usedNumbers[spec.Index] {
				return nil, fmt.Errorf("cannot create %q at partition %d: slot occupied by a different GUID", spec.Label, spec.Index)
			}
			targets = append(targets, partitionResizeTarget{
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
		// Matched by GUID: assert identity so we never touch an unexpected disk.
		if spec.TypeGUID != "" && !strings.EqualFold(string(p.Type), spec.TypeGUID) {
			return nil, fmt.Errorf("partition %q (GUID %s): type %s does not match expected %s", spec.Label, guid, p.Type, spec.TypeGUID)
		}
		if spec.Label != "" && p.Name != spec.Label {
			return nil, fmt.Errorf("partition GUID %s: label %q does not match expected %q", guid, p.Name, spec.Label)
		}
		if p.GetSize() >= spec.MinSize {
			// Already at least MinSize: never shrink. A requested index change on
			// an otherwise-satisfied partition (metadata-only renumber) is not yet
			// implemented; flag it rather than silently ignoring it.
			if spec.Index != 0 && p.Index != spec.Index {
				return nil, fmt.Errorf("partition %q is already sized but has number %d, not requested %d (metadata-only renumber unimplemented)", spec.Label, p.Index, spec.Index)
			}
			continue
		}
		// Grow: relocate + copy, preserving the partition number.
		orig := gptToData(p)
		tgt := orig
		tgt.size = spec.MinSize
		targets = append(targets, partitionResizeTarget{original: orig, target: tgt})
	}

	if shrink != nil {
		sd, err := matchTableIdentifier(table, shrink.ID)
		if err != nil {
			return nil, err
		}
		if sd.size > shrink.Size {
			tgt := sd
			tgt.size = shrink.Size
			tgt.start = sd.start // shrink in place
			tgt.end = sd.start + shrink.Size - 1
			targets = append(targets, partitionResizeTarget{original: sd, target: tgt})
		}
	}
	return targets, nil
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
