// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"io/fs"
	"reflect"
	"sort"
	"testing"
	"testing/fstest"
)

func TestReadEfiVars(t *testing.T) {
	tests := []struct {
		name    string
		fsys    fstest.MapFS
		want    []efiVariable
		wantErr bool
	}{
		{
			name: "successful read with multiple boot variables",
			fsys: fstest.MapFS{
				"BootOrder": &fstest.MapFile{Data: []byte{0x01, 0x02}},
				"Boot0001":  &fstest.MapFile{Data: []byte("var1")},
				"Boot0002":  &fstest.MapFile{Data: []byte("var2")},
				"BootDir":   &fstest.MapFile{Mode: fs.ModeDir},        // Should be skipped
				"Invalid":   &fstest.MapFile{Data: []byte("invalid")}, // Doesn't match regex
			},
			want: []efiVariable{
				{Name: "BootOrder", Value: []byte{0x01, 0x02}},
				{Name: "Boot0001", Value: []byte("var1")},
				{Name: "Boot0002", Value: []byte("var2")},
			},
			wantErr: false,
		},
		{
			name: "missing BootOrder file",
			fsys: fstest.MapFS{
				"Boot0001": &fstest.MapFile{Data: []byte("var1")},
			},
			want:    []efiVariable{},
			wantErr: true,
		},
		{
			name: "invalid boot variable",
			fsys: fstest.MapFS{
				"BootOrder": &fstest.MapFile{Data: []byte{0x01, 0x02}},
				"Boot123":   &fstest.MapFile{Data: []byte("var1")}, // Doesn't match regex
				"Boot0001":  &fstest.MapFile{Data: []byte("var1")},
			},
			want: []efiVariable{
				{Name: "Boot0001", Value: []byte("var1")},
				{Name: "BootOrder", Value: []byte{0x01, 0x02}},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readEfiVars(tt.fsys)
			if (err != nil) != tt.wantErr {
				t.Logf("Test: %s", tt.name)
				t.Fatalf("readEfiVars() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				// Sort boot variables for consistent comparison
				sortBootVars(got)
				sortBootVars(tt.want)
				if !reflect.DeepEqual(got, tt.want) {
					t.Logf("Test: %s", tt.name)
					t.Fatalf("readEfiVars() = %+v, want %+v", got, tt.want)
				}
			}
		})
	}
}

// sortBootVars sorts boot variables by Name
func sortBootVars(vars []efiVariable) {
	sort.Slice(vars, func(i, j int) bool {
		return vars[i].Name < vars[j].Name
	})
}
