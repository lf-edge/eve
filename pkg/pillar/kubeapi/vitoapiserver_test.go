// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"fmt"
	"math"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// TestPVCRequestSize checks the sizes a claim is allowed to ask for. The
// decimal-unit cases are the ones seen in the field (lf-edge/eve#6331): a size
// expressed in MB/GB is never a multiple of Longhorn's 2 MiB granularity, so
// without rounding the provisioned volume exceeds the claim and CDI rejects the
// import.
func TestPVCRequestSize(t *testing.T) {
	tests := []struct {
		name string
		size uint64
		want uint64
	}{
		{"1GB decimal", 1000000000, 1000341504},
		{"100MB decimal", 100000000, 100663296},
		{"5GB decimal above 4GiB", 5000000000, 5001707520},
		{"12MB decimal", 12000000, 12582912},
		{"1GiB already aligned", 1073741824, 1073741824},
		{"minimum already aligned", 10485760, 10485760},
		{"one byte below minimum", 10485759, 10485760},
		{"below minimum and unaligned", 2097153, 10485760},
		{"one byte below a block boundary", 4194303, 10485760},
		{"zero", 0, 10485760},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pvcRequestSize(tt.size); got != tt.want {
				t.Errorf("pvcRequestSize(%d) = %d, want %d", tt.size, got, tt.want)
			}
		})
	}
}

// TestPVCRequestSizeAppliesMinimumBeforeRounding pins the order of the two
// adjustments. Rounding an unaligned sub-minimum size first would yield a claim
// below the minimum Longhorn accepts, which the table above cannot distinguish
// from a correct result for aligned inputs.
func TestPVCRequestSizeAppliesMinimumBeforeRounding(t *testing.T) {
	const justOverOneBlock = longhornVolumeBlockSize + 1
	got := pvcRequestSize(justOverOneBlock)
	if got != pvcMinSize {
		t.Errorf("pvcRequestSize(%d) = %d, want the minimum %d; the minimum must be applied before rounding",
			justOverOneBlock, got, pvcMinSize)
	}
}

// TestPVCRequestSizeInvariants asserts the properties every claim size must
// satisfy: it is aligned to Longhorn's granularity (the reason the rounding
// exists), it never shrinks (a smaller claim would truncate the image), it never
// drops below the supported minimum, and it is stable under a second
// application -- RolloutDiskToPVC raises the size to the image's virtual size
// before calling CreatePVC, so a size can pass through this more than once.
func TestPVCRequestSizeInvariants(t *testing.T) {
	sizes := []uint64{
		0, 1, 512, 4096, pvcMinSize - 1, pvcMinSize, pvcMinSize + 1,
		12000000, 100000000, 1000000000, 1073741824, 5000000000,
		longhornVolumeBlockSize - 1, longhornVolumeBlockSize, longhornVolumeBlockSize + 1,
		1 << 40, (1 << 40) + 1, 1<<44 - 3,
	}
	for i := uint64(1); i <= 64; i++ {
		sizes = append(sizes, i*7919999)
	}
	for _, size := range sizes {
		got := pvcRequestSize(size)
		if got%longhornVolumeBlockSize != 0 {
			t.Errorf("pvcRequestSize(%d) = %d, not a multiple of %d", size, got, longhornVolumeBlockSize)
		}
		if got < size {
			t.Errorf("pvcRequestSize(%d) = %d, must never shrink the request", size, got)
		}
		if got < pvcMinSize {
			t.Errorf("pvcRequestSize(%d) = %d, below the minimum %d", size, got, pvcMinSize)
		}
		if again := pvcRequestSize(got); again != got {
			t.Errorf("pvcRequestSize(%d) = %d, applying it again gave %d; must be idempotent", size, got, again)
		}
	}
}

// TestPVCRequestSizeNoOverflow covers the sizes within one block of the uint64
// range, where padding up to the next multiple would wrap and hand back a claim
// far smaller than requested.
func TestPVCRequestSizeNoOverflow(t *testing.T) {
	for _, size := range []uint64{math.MaxUint64, math.MaxUint64 - 1, math.MaxUint64 - longhornVolumeBlockSize + 1} {
		if got := pvcRequestSize(size); got < size {
			t.Errorf("pvcRequestSize(%d) = %d, overflowed instead of leaving the size alone", size, got)
		}
	}
}

// TestNewPVCDefinitionRequestsRoundedSize checks the value that actually reaches
// Longhorn and CDI: the storage quantity in the claim spec, after the size has
// been through the string formatting CreatePVC applies.
func TestNewPVCDefinitionRequestsRoundedSize(t *testing.T) {
	const requested = 1000000000
	rounded := pvcRequestSize(requested)

	pvc := NewPVCDefinition("test-pvc", fmt.Sprint(rounded), nil, nil, "longhorn")
	quantity, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	if !ok {
		t.Fatal("NewPVCDefinition produced no storage request")
	}
	got := quantity.Value()
	if got != int64(rounded) {
		t.Errorf("claim requests %d bytes, want %d", got, rounded)
	}
	if got%longhornVolumeBlockSize != 0 {
		t.Errorf("claim requests %d bytes, not a multiple of %d", got, longhornVolumeBlockSize)
	}
}
