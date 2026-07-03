package partitionresizer

import (
	"fmt"

	"github.com/diskfs/go-diskfs/partition"
)

// partitionIdentifiersToData converts the given PartitionIdentifier slice to partition data on the given disk
func partitionIdentifiersToData(disk partition.Table, diskPartitionData []partitionData, partitionIDs []PartitionIdentifier) ([]partitionData, error) {
	// parts gives us the partition table information on the disk; it does not help us with the
	// name, e.g. sda2 or vda6, since that is a local reference only, not on the disk itself.
	// We can get that from diskPartitionData
	// in the end, we have the table, so we just want to know the partition indexes
	namePartMapping := make(map[string]partitionData)
	for _, pd := range diskPartitionData {
		namePartMapping[pd.name] = pd
	}
	parts := disk.GetPartitions()
	var data []partitionData
	for _, pi := range partitionIDs {
		found := false
		for _, p := range parts {
			var match bool
			switch pi.By() {
			case IdentifierByName:
				mapped, ok := namePartMapping[pi.Value()]
				if ok && mapped.number == p.GetIndex() {
					match = true
				}
			case IdentifierByLabel:
				if p.Label() == pi.Value() {
					match = true
				}
			case IdentifierByUUID:
				if p.UUID() == pi.Value() {
					match = true
				}
			}
			if match {
				data = append(data, partitionData{
					label:  p.Label(),
					size:   p.GetSize(),
					start:  p.GetStart(),
					end:    p.GetStart() + p.GetSize() - 1,
					number: p.GetIndex(),
				})
				found = true
				break
			}
		}
		if !found {
			// keep original change if not found
			return nil, fmt.Errorf("could not find partition for identifier: %s=%s", pi.By(), pi.Value())
		}
	}
	return data, nil
}

// partitionChangesToResizeTarget converts the given PartitionChange slice to partition resize target on the given disk
func partitionChangesToResizeTarget(disk partition.Table, diskPartitionData []partitionData, partitionChanges []PartitionChange) ([]partitionResizeTarget, error) {
	var partitionIdentifiers []PartitionIdentifier
	for _, pc := range partitionChanges {
		partitionIdentifiers = append(partitionIdentifiers, pc)
	}
	updatedData, err := partitionIdentifiersToData(disk, diskPartitionData, partitionIdentifiers)
	if err != nil {
		return nil, err
	}
	if len(updatedData) != len(partitionChanges) {
		return nil, fmt.Errorf("mismatched partition data and changes lengths")
	}
	var res []partitionResizeTarget
	for i, pc := range partitionChanges {
		res = append(res, partitionResizeTarget{
			original: updatedData[i],
			target: partitionData{
				size: pc.Size(),
			},
		})
	}
	return res, nil
}
