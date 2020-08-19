// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"testing"
)

func TestBiosFieldsHandling(t *testing.T) {
	biosTestParams := []struct {
		biosVendor      string
		biosVersion     string
		biosReleaseDate string
		expectedStr     string
	}{
		{"", "", "", ""},
		{"", "", "c", "c"},
		{"", "b", "", "b"},
		{"", "b", "c", "b-c"},
		{"a", "", "", "a"},
		{"a", "", "c", "a-c"},
		{"a", "b", "", "a-b"},
		{"a", "b", "c", "a-b-c"},
	}
	for _, testFields := range biosTestParams {
		resultStr := combineBiosFields(testFields.biosVendor,
			testFields.biosVersion,
			testFields.biosReleaseDate)
		if resultStr != testFields.expectedStr {
			t.Errorf("want %s, but got %s", testFields.expectedStr, resultStr)
		}
	}
}
