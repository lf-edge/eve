// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
	"sort"
	"testing"

	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInit(t *testing.T) {
	testMatrix := map[string]struct {
		reservedCPUs   uint32
		totalCPUs      uint32
		expectInitFail bool
	}{
		"init good": {
			totalCPUs:    16,
			reservedCPUs: 2,
		},
		"init bad": {
			totalCPUs:      16,
			reservedCPUs:   32,
			expectInitFail: true,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		t.Run(testname, func(t *testing.T) {
			ca, err := Init(test.totalCPUs, test.reservedCPUs)
			if err != nil {
				t.Logf("Init returned %s", err)
			}
			if test.expectInitFail {
				assert.NotNil(t, err)
				return
			}
			assert.Nil(t, err)
			all := ca.GetAllFree()
			t.Logf("GetAllFree returned %v", all)
			assert.Equal(t, test.totalCPUs, uint32(len(all)))
		})
	}
}

type tm struct {
	description      string
	uuid             uuid.UUID
	doFree           bool // otherwise allocate
	allocate         int  // number of CPUs
	free             int  // number of CPUs
	expectFail       bool
	expectAllocation []uint32
	expectAllFree    []uint32
}

func TestAllocate(t *testing.T) {
	uuid1, _ := uuid.NewV4()
	uuid2, _ := uuid.NewV4()
	uuid3, _ := uuid.NewV4()
	uuid4, _ := uuid.NewV4()
	uuid5, _ := uuid.NewV4()
	uuid6, _ := uuid.NewV4()
	uuid7, _ := uuid.NewV4()

	testSequence := make([]tm, 0)
	testSequence = append(testSequence,
		tm{
			description:   "allocate bad",
			uuid:          uuid1,
			allocate:      16,
			expectFail:    true,
			expectAllFree: []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{

			description:      "allocate good",
			uuid:             uuid1,
			allocate:         8,
			expectAllocation: []uint32{2, 3, 4, 5, 6, 7, 8, 9},
			expectAllFree:    []uint32{0, 1, 10, 11, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:   "allocate too many",
			uuid:          uuid2,
			allocate:      8,
			expectFail:    true,
			expectAllFree: []uint32{0, 1, 10, 11, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:      "allocate less",
			uuid:             uuid2,
			allocate:         2,
			expectAllocation: []uint32{10, 11},
			expectAllFree:    []uint32{0, 1, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:   "free 8",
			uuid:          uuid1,
			doFree:        true,
			free:          8, // from "allocate good" above
			expectAllFree: []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:      "allocate many after free",
			uuid:             uuid3,
			allocate:         8,
			expectAllocation: []uint32{2, 3, 4, 5, 6, 7, 8, 9},
			expectAllFree:    []uint32{0, 1, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:   "allocate again",
			uuid:          uuid3,
			allocate:      9,
			expectFail:    true,
			expectAllFree: []uint32{0, 1, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:   "free without allocate",
			uuid:          uuid4,
			doFree:        true,
			free:          0,
			expectFail:    true,
			expectAllFree: []uint32{0, 1, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:   "double free 8",
			uuid:          uuid1,
			doFree:        true,
			free:          8, // from "allocate good" above
			expectFail:    true,
			expectAllFree: []uint32{0, 1, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:      "allocate remaining free",
			uuid:             uuid5,
			allocate:         4,
			expectAllocation: []uint32{12, 13, 14, 15},
			expectAllFree:    []uint32{0, 1},
		})
	testSequence = append(testSequence,
		tm{
			description:      "allocate none",
			uuid:             uuid6,
			allocate:         0,
			expectAllocation: []uint32{},
			expectAllFree:    []uint32{0, 1},
		})
	testSequence = append(testSequence,
		tm{
			description:   "allocate one",
			uuid:          uuid7,
			allocate:      1,
			expectFail:    true,
			expectAllFree: []uint32{0, 1},
		})

	ca, err := Init(16, 2)
	available := 16 // For GetAllFree
	assert.Nil(t, err)
	t.Logf("Running %d in sequence", len(testSequence))
	for _, test := range testSequence {
		t.Logf("Running test case %s", test.description)
		if test.doFree {
			err := ca.Free(test.uuid)
			if err != nil {
				t.Logf("Free returned %s", err)
			}
			if test.expectFail {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				available += test.free
			}
		} else {
			some, err := ca.Allocate(test.uuid, test.allocate)
			if err != nil {
				t.Logf("Allocate returned %s", err)
			}
			if test.expectFail {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				t.Logf("Allocate returned %v", some)
				assert.Equal(t, test.allocate, len(some))
				assert.Equal(t, test.expectAllocation, some)
				available -= test.allocate
			}
		}
		all := ca.GetAllFree()
		t.Logf("GetAllFree returned %v", all)
		assert.Equal(t, available, len(all))
		assert.Equal(t, test.expectAllFree, all)
	}
}

// TestAllocateRT_IsolatedCPUs verifies that AllocateRT only hands out
// cores that are in the isolcpus= set.  Non-isolated (housekeeping)
// cores must never be given to an RT container, even when they are
// free and belong to the same L3 domain.
func TestAllocateRT_IsolatedCPUs(t *testing.T) {
	// Simulate a 16-core system, 2 reserved for EVE (cores 0-1).
	// Two L3 domains:
	//   domain 0: cores 0-7
	//   domain 1: cores 8-15
	// isolcpus = 3,4,5,6,7,11,12,13,14,15   (cores 2,8,9,10 are housekeeping)
	topo := &TopologyInfo{
		NumCores:   16,
		RDTCapable: true,
		L3Domains: []L3Domain{
			{
				L3CATID:   0,
				Cores:     []uint32{0, 1, 2, 3, 4, 5, 6, 7},
				NumWays:   12,
				WaySize:   1 << 20,
				CacheSize: 12 * (1 << 20),
			},
			{
				L3CATID:   1,
				Cores:     []uint32{8, 9, 10, 11, 12, 13, 14, 15},
				NumWays:   12,
				WaySize:   1 << 20,
				CacheSize: 12 * (1 << 20),
			},
		},
		NUMANodes: []NUMANode{
			{ID: 0, Cores: []uint32{0, 1, 2, 3, 4, 5, 6, 7}, L3Domains: []uint{0}},
			{ID: 1, Cores: []uint32{8, 9, 10, 11, 12, 13, 14, 15}, L3Domains: []uint{1}},
		},
		IsolatedCPUs: []uint32{3, 4, 5, 6, 7, 11, 12, 13, 14, 15},
	}

	alloc, err := InitTopoAware(topo, 2)
	require.NoError(t, err)

	id1, _ := uuid.NewV4()

	// Ask for 3 RT cores.  Domain 0 has isolated cores {3,4,5,6,7} (5 free)
	// and domain 1 has {11,12,13,14,15} (5 free).  Either domain can
	// satisfy the request, but NO allocated core should be 2, 8, 9, or 10.
	result := alloc.AllocateRT(id1, 3)
	require.Equal(t, AllocSuccess, result.Status, result.Message)
	require.Len(t, result.Cores, 3)

	for _, c := range result.Cores {
		assert.True(t, topo.IsIsolated(c),
			"RT allocation returned non-isolated core %d", c)
	}

	// All cores must come from the same L3 domain.
	allSameDomain := true
	for _, c := range result.Cores {
		found := false
		for _, l3 := range topo.L3Domains {
			if l3.L3CATID == result.L3CATID {
				for _, dc := range l3.Cores {
					if dc == c {
						found = true
						break
					}
				}
				break
			}
		}
		if !found {
			allSameDomain = false
		}
	}
	assert.True(t, allSameDomain,
		"cores %v do not all belong to L3 domain %d", result.Cores, result.L3CATID)

	// Allocate a second RT container that needs 4 cores.
	// After the first allocation consumed 3 isolated cores from one domain,
	// both domains still have enough isolated cores (either 2 or 5).
	// The allocator should pick a domain that can satisfy 4.
	id2, _ := uuid.NewV4()
	result2 := alloc.AllocateRT(id2, 4)
	require.Equal(t, AllocSuccess, result2.Status, result2.Message)
	require.Len(t, result2.Cores, 4)

	for _, c := range result2.Cores {
		assert.True(t, topo.IsIsolated(c),
			"RT allocation returned non-isolated core %d", c)
	}

	// The two allocations must not share any cores.
	coreSet := map[uint32]bool{}
	for _, c := range result.Cores {
		coreSet[c] = true
	}
	for _, c := range result2.Cores {
		assert.False(t, coreSet[c],
			"core %d allocated to both containers", c)
	}
}

// TestAllocateRT_NoIsolcpus verifies that when isolcpus is empty (no
// kernel isolation), AllocateRT falls back to using any non-reserved
// core — it should not refuse to allocate.
func TestAllocateRT_NoIsolcpus(t *testing.T) {
	topo := &TopologyInfo{
		NumCores:   8,
		RDTCapable: true,
		L3Domains: []L3Domain{
			{
				L3CATID:   0,
				Cores:     []uint32{0, 1, 2, 3, 4, 5, 6, 7},
				NumWays:   12,
				WaySize:   1 << 20,
				CacheSize: 12 * (1 << 20),
			},
		},
		NUMANodes: []NUMANode{
			{ID: 0, Cores: []uint32{0, 1, 2, 3, 4, 5, 6, 7}, L3Domains: []uint{0}},
		},
		IsolatedCPUs: nil, // no isolcpus
	}

	alloc, err := InitTopoAware(topo, 2)
	require.NoError(t, err)

	id1, _ := uuid.NewV4()
	result := alloc.AllocateRT(id1, 4)
	require.Equal(t, AllocSuccess, result.Status, result.Message)
	require.Len(t, result.Cores, 4)

	sorted := make([]uint32, len(result.Cores))
	copy(sorted, result.Cores)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	// With 2 reserved (0,1), the free non-reserved cores are 2..7.
	// Should pick the first 4: {2,3,4,5}.
	assert.Equal(t, []uint32{2, 3, 4, 5}, sorted)
}

// TestAllocateRT_InsufficientIsolated verifies that when the request
// cannot be satisfied using only isolated cores, the allocator returns
// the appropriate failure status instead of silently handing out
// housekeeping cores.
func TestAllocateRT_InsufficientIsolated(t *testing.T) {
	// 8 cores, 2 reserved; only cores 4 and 5 are isolated.
	topo := &TopologyInfo{
		NumCores:   8,
		RDTCapable: true,
		L3Domains: []L3Domain{
			{
				L3CATID:   0,
				Cores:     []uint32{0, 1, 2, 3, 4, 5, 6, 7},
				NumWays:   12,
				WaySize:   1 << 20,
				CacheSize: 12 * (1 << 20),
			},
		},
		NUMANodes: []NUMANode{
			{ID: 0, Cores: []uint32{0, 1, 2, 3, 4, 5, 6, 7}, L3Domains: []uint{0}},
		},
		IsolatedCPUs: []uint32{4, 5},
	}

	alloc, err := InitTopoAware(topo, 2)
	require.NoError(t, err)

	id1, _ := uuid.NewV4()
	// Ask for 3 cores but only 2 are isolated — must fail.
	result := alloc.AllocateRT(id1, 3)
	assert.NotEqual(t, AllocSuccess, result.Status,
		"should not succeed when not enough isolated cores; got cores %v", result.Cores)
}
