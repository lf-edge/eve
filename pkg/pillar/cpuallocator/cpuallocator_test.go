// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
	"testing"

	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {
	testMatrix := map[string]struct {
		reservedCPUs   int
		totalCPUs      int
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
			assert.Equal(t, test.totalCPUs, len(all))
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
	expectAllocation []int
	expectAllFree    []int
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
			expectAllFree: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{

			description:      "allocate good",
			uuid:             uuid1,
			allocate:         8,
			expectAllocation: []int{2, 3, 4, 5, 6, 7, 8, 9},
			expectAllFree:    []int{0, 1, 10, 11, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:   "allocate too many",
			uuid:          uuid2,
			allocate:      8,
			expectFail:    true,
			expectAllFree: []int{0, 1, 10, 11, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:      "allocate less",
			uuid:             uuid2,
			allocate:         2,
			expectAllocation: []int{10, 11},
			expectAllFree:    []int{0, 1, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:   "free 8",
			uuid:          uuid1,
			doFree:        true,
			free:          8, // from "allocate good" above
			expectAllFree: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:      "allocate many after free",
			uuid:             uuid3,
			allocate:         8,
			expectAllocation: []int{2, 3, 4, 5, 6, 7, 8, 9},
			expectAllFree:    []int{0, 1, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:   "allocate again",
			uuid:          uuid3,
			allocate:      9,
			expectFail:    true,
			expectAllFree: []int{0, 1, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:   "free without allocate",
			uuid:          uuid4,
			doFree:        true,
			free:          0,
			expectFail:    true,
			expectAllFree: []int{0, 1, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:   "double free 8",
			uuid:          uuid1,
			doFree:        true,
			free:          8, // from "allocate good" above
			expectFail:    true,
			expectAllFree: []int{0, 1, 12, 13, 14, 15},
		})
	testSequence = append(testSequence,
		tm{
			description:      "allocate remaining free",
			uuid:             uuid5,
			allocate:         4,
			expectAllocation: []int{12, 13, 14, 15},
			expectAllFree:    []int{0, 1},
		})
	testSequence = append(testSequence,
		tm{
			description:      "allocate none",
			uuid:             uuid6,
			allocate:         0,
			expectAllocation: []int{},
			expectAllFree:    []int{0, 1},
		})
	testSequence = append(testSequence,
		tm{
			description:   "allocate one",
			uuid:          uuid7,
			allocate:      1,
			expectFail:    true,
			expectAllFree: []int{0, 1},
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
