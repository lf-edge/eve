// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pkg

import (
	"strings"
	"testing"
	"unicode"
)

func TestStartCol(t *testing.T) {
	oldCode := "package main\n"
	newCode := "package main\n\n/* a comment\n   \n*/\nfunc main() {\n\t\tfmt.Println()\n}\n"

	fromLines := strings.Split(oldCode, "\n")
	toLines := strings.Split(newCode, "\n")
	toProps := Parse("main.go", newCode)

	dfs := Diff(fromLines, toLines)
	for i := range dfs {
		if dfs[i].Operation == LineAdd {
			dfs[i].TypeOfLine = toProps[uint32(dfs[i].LineNumber)]
		}
	}

	tests := []struct {
		name string
		line string
		want int
	}{
		{"indented code", "\t\tfmt.Println()", 2},
		{"all whitespace", "   ", 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			found := false
			for _, df := range dfs {
				if df.Line == tc.line {
					found = true
					if got := df.startCol(); got != tc.want {
						t.Errorf("startCol() on %q: got %d, want %d", tc.line, got, tc.want)
					}
				}
			}
			if !found {
				t.Fatalf("line %q not found in diff", tc.line)
			}
		})
	}
}

func startColFixed(line string) int {
	for i, r := range []rune(line) {
		if !unicode.IsSpace(r) {
			return i
		}
	}
	return len([]rune(line))
}

func FuzzStartCol(f *testing.F) {
	f.Add("hello")
	f.Add("\t\tfmt.Println()")
	f.Add("  foo")
	f.Add("\t x")

	f.Fuzz(func(t *testing.T, line string) {
		allWhitespace := true
		for _, r := range line {
			if !unicode.IsSpace(r) {
				allWhitespace = false
				break
			}
		}
		if allWhitespace {
			t.Skip("skipping all-whitespace input")
		}

		ld := LineDiff{Line: line}
		got := ld.startCol()
		want := startColFixed(line)
		if got != want {
			t.Errorf("startCol() on %q: got %d, want %d", line, got, want)
		}
	})
}
