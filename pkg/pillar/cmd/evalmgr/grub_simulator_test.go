// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// GRUB gptprio.c boot selection algorithm (from pkg/grub/patches-2.06/0002-Add-gptprio-module.patch):
//
//   for (i = 0; (part = grub_gpt_get_partentry (gpt, i)) != NULL; i++)
//     {
//       // ... extract partition attributes ...
//       priority = grub_gptprio_priority (part);
//       tries_left = grub_gptprio_tries_left (part);
//       successful = grub_gptprio_successful (part);
//
//       if (part_found)
//         old_priority = grub_gptprio_priority (part_found);
//
//       // Key selection logic:
//       if ((tries_left || successful) && priority > old_priority)
//         {
//           part_index = i;
//           part_found = part;    // Remember partition with highest priority seen so far
//         }
//     }
//
//   // ... error if no partition found ...
//
//   // Decrement tries_left before booting:
//   if (grub_gptprio_tries_left (part_found))
//     {
//       unsigned int tries_left = grub_gptprio_tries_left (part_found);
//       grub_gptprio_set_tries_left (part_found, tries_left - 1);
//       // ... write to disk ...
//     }
//
// CRITICAL BEHAVIORS:
// 1. Iterates through ALL partitions in order
// 2. Partition is bootable if: (tries_left > 0 OR successful) AND priority > 0
// 3. Selects partition with HIGHEST priority among bootable partitions
// 4. NO alphabetical tie-breaking - first partition with max priority wins
// 5. Decrements tries_left (if > 0) BEFORE booting

// SimulateGrubBoot simulates a GRUB boot cycle on the given GPT accessor
// This implements the GRUB gptprio boot selection algorithm exactly as GRUB does it.
//
// Algorithm (from GRUB gptprio.c):
// 1. Iterate through all partitions
// 2. For each partition, check if bootable: (tries_left > 0 OR successful) AND priority > 0
// 3. Among bootable partitions, select the one with HIGHEST priority
// 4. If multiple partitions have same highest priority, first one wins (no alphabetical sorting)
// 5. Decrement tries_left if > 0
// 6. Return selected partition
func SimulateGrubBoot(gpt GptAttributeAccess, log *base.LogObject) (string, error) {
	var partitionFound string
	var oldPriority int
	validLabels := gpt.GetValidPartitionLabels()

	// Step 1 & 2: Iterate through all partitions and find the one with highest priority
	for _, label := range validLabels {
		attr, err := gpt.GetPartitionAttributes(label)
		if err != nil {
			if log != nil {
				log.Warnf("Failed to read attributes for %s: %v", label, err)
			}
			continue
		}

		// Extract fields from attribute
		priority := int(attr & 0xF)
		triesLeft := int((attr >> 4) & 0xF)
		successful := (attr & (1 << 8)) != 0

		// Step 2: Check if bootable: (tries_left > 0 OR successful) AND priority > 0
		isBootable := (triesLeft > 0 || successful) && priority > 0

		// Step 3: Select partition with highest priority
		// IMPORTANT: This matches GRUB's logic exactly:
		//   if ((tries_left || successful) && priority > old_priority)
		if isBootable && priority > oldPriority {
			partitionFound = label
			oldPriority = priority
		}
	}

	// No bootable partition found
	if partitionFound == "" {
		return "", fmt.Errorf("no bootable partitions found")
	}

	// Step 5: Decrement tries_left if > 0 (before booting)
	attr, err := gpt.GetPartitionAttributes(partitionFound)
	if err != nil {
		return "", fmt.Errorf("failed to read attributes for selected partition %s: %w", partitionFound, err)
	}

	triesLeft := int((attr >> 4) & 0xF)
	if triesLeft > 0 {
		triesLeft--
		priority := int(attr & 0xF)
		successful := (attr & (1 << 8)) != 0

		// Re-encode attribute with decremented tries
		attr = uint16(priority) | (uint16(triesLeft) << 4)
		if successful {
			attr |= (1 << 8)
		}

		err = gpt.SetPartitionAttributes(partitionFound, attr)
		if err != nil {
			return "", fmt.Errorf("failed to update tries for %s: %w", partitionFound, err)
		}
	}

	// Step 6: Return selected partition
	if log != nil {
		log.Noticef("GRUB selected partition: %s (priority=%d)", partitionFound, oldPriority)
	}

	return partitionFound, nil
}
