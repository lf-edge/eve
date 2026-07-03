package partitionresizer

import (
	"fmt"
	"sort"

	"github.com/diskfs/go-diskfs/partition/gpt"
)

// usableBlock represents a block of usable space on the disk, it might be used or unused, depending
// on its context. start, end and size are all in bytes.
type usableBlock struct {
	start int64
	end   int64
	size  int64
}

// calculateResizes determines the necessary resize operations to perform
// based on the current partitions, the partition to shrink (if any), and
// the partitions to grow. Assume we will not be growing the partitions,
// but creating new ones in the free space, copying over and deleting the old ones.
func calculateResizes(size int64, parts []*gpt.Partition, partitionResizes []partitionResizeTarget) (resizes []partitionResizeTarget, err error) {
	// find the free space on the disk
	var used, unused []usableBlock
	// get a list of all of the used space
	for _, p := range parts {
		used = append(used, usableBlock{start: p.GetStart(), end: p.GetSize() + p.GetStart() - 1, size: p.GetSize()})
	}
	sort.Slice(used, func(i, j int) bool {
		return used[i].start < used[j].start
	})
	unused = computeUnused(size, used)

	// find the available partition slot numbers
	var (
		// list of used partitions
		usedPartitionNumbers = make(map[int]bool)
	)
	for _, p := range parts {
		usedPartitionNumbers[int(p.Index)] = true
	}
	// Reserve any explicitly requested partition numbers (create targets that ask
	// for a specific slot, e.g. ESP-B at #7) up front, so the lowest-free
	// assignment for relocated grows below cannot claim them.
	for _, gp := range partitionResizes {
		if gp.create && gp.target.number != 0 {
			if usedPartitionNumbers[gp.target.number] {
				return nil, fmt.Errorf("requested partition number %d for %q is already in use", gp.target.number, gp.target.label)
			}
			usedPartitionNumbers[gp.target.number] = true
		}
	}

	// now go through each of the grow partitions and find space for them
	for i, gp := range partitionResizes {
		// if one of these is a shrink, then allocate the space for it
		if gp.target.size < gp.original.size {
			// shrinking, so just adjust in place
			gp.target.start = gp.original.start
			gp.target.end = gp.target.start + gp.target.size - 1
			gp.target.number = gp.original.number
			resizes = append(resizes, gp)
			// update our free space
			unused = append(unused, usableBlock{
				start: gp.target.end + 1,
				end:   gp.original.end,
			})
			// keep unused sorted and combine as needed
			unused = sortAndCombineUsableBlocks(unused)
			continue
		}
		found := false
		for j := 0; j < len(unused); j++ {
			u := &unused[j]
			available := u.end - u.start + 1
			if available >= gp.target.size {
				// allocate at the start of this gap
				gp.target.start = u.start
				gp.target.end = u.start + gp.target.size - 1
				u.start += gp.target.size
				if u.start > u.end {
					unused = append(unused[:j], unused[j+1:]...)
				}
				// A create that requested a specific number keeps it (reserved
				// above). Everything else (relocated grows) takes the lowest free
				// number; updatePartitions renumbers relocated grows back to their
				// original number afterwards.
				if !gp.create || gp.target.number == 0 {
					for pn := 1; ; pn++ {
						if !usedPartitionNumbers[pn] {
							gp.target.number = pn
							usedPartitionNumbers[pn] = true
							break
						}
					}
				}
				found = true
				break
			}
		}
		if !found {
			return nil, NewInsufficientSpaceError(partitionResizes[i].original.label, partitionResizes[i].target.size)
		}
		resizes = append(resizes, gp)
	}

	return resizes, nil
}

func computeUnused(size int64, used []usableBlock) []usableBlock {
	var unused []usableBlock

	var prevEnd int64 = 0

	for _, u := range used {
		// gap before this used block
		if u.start > prevEnd+1 {
			unused = append(unused, usableBlock{
				start: prevEnd + 1,
				end:   u.start - 1,
			})
		}
		prevEnd = u.end
	}

	// gap after last used block
	if prevEnd < size-1 {
		unused = append(unused, usableBlock{
			start: prevEnd + 1,
			end:   size - 1,
		})
	}

	return unused
}

func sortAndCombineUsableBlocks(blocks []usableBlock) []usableBlock {
	if len(blocks) == 0 {
		return blocks
	}
	sort.Slice(blocks, func(i, j int) bool {
		return blocks[i].start < blocks[j].start
	})
	var combined []usableBlock
	current := blocks[0]
	for i := 1; i < len(blocks); i++ {
		b := blocks[i]
		if current.end+1 >= b.start {
			// overlapping or adjacent, combine
			if b.end > current.end {
				current.end = b.end
			}
		} else {
			combined = append(combined, current)
			current = b
		}
	}
	combined = append(combined, current)
	return combined
}
