// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pkg

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func lcsSimple(from, to []string, fromIndex, toIndex, count int) int {
	if fromIndex == 0 {
		return count
	}
	if toIndex == 0 {
		return count
	}

	lastFromStr := from[fromIndex-1]
	lastToStr := to[toIndex-1]
	if lastFromStr == lastToStr {
		return lcsSimple(from, to, fromIndex-1, toIndex-1, count+1)
	} else {
		return max(lcsSimple(from, to, fromIndex-1, toIndex, count), lcsSimple(from, to, fromIndex, toIndex-1, count))
	}
}

func backtrackSimple(from, to []string, fromIndex, toIndex int) []string {
	if fromIndex == 0 {
		return []string{}
	}
	if toIndex == 0 {
		return []string{}
	}

	lastFromStr := from[fromIndex-1]
	lastToStr := to[toIndex-1]
	if lastFromStr == lastToStr {
		return append(backtrackSimple(from, to, fromIndex-1, toIndex-1), lastFromStr)
	}

	if lcsSimple(from, to, fromIndex, toIndex-1, 0) > lcsSimple(from, to, fromIndex-1, toIndex, 0) {
		return backtrackSimple(from, to, fromIndex, toIndex-1)
	}
	return backtrackSimple(from, to, fromIndex-1, toIndex)
}

func TestBacktrack(t *testing.T) {
	from := strings.Split("AGCATDC", "")
	to := strings.Split("GACDC", "")

	l := backtrackSimple(from, to, len(from), len(to))

	if strings.Join(l, "") != "ACDC" {
		t.Logf("backtrack: %s\n", l)
	}
}

func TestShaveLast(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		str  []string
		want []string
	}{
		{
			name: "empty",
			str:  []string{},
			want: []string{},
		},
		{
			name: "one element",
			str:  []string{"foo"},
			want: []string{},
		},
		{
			name: "two elements",
			str:  []string{"foo", "bar"},
			want: []string{"foo"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shaveLast(tt.str)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("shaveLast() = %v, want %v", got, tt.want)
			}
		})
	}
}

func FuzzLCS(f *testing.F) {
	f.Fuzz(func(t *testing.T, fromStr, toStr string) {
		from := strings.Split(fromStr, "")
		to := strings.Split(toStr, "")

		maxLen := 9
		if len(from) > maxLen || len(to) > maxLen {
			return
		}

		l1 := lcsSimple(from, to, len(from), len(to), 0)

		l2 := lcs(from, to)

		if l1 != l2 {
			t.Fatalf("got two different solutions %d/%d for '%s' <-> '%s'", l1, l2, from, to)
		}
	})
}

// func FuzzLCSDiff(f *testing.F) {
// 	f.Fuzz(func(t *testing.T, fromStr, toStr string) {
// 		from := strings.Split(fromStr, "")
// 		to := strings.Split(toStr, "")

// 		maxLen := 99999
// 		if len(from) > maxLen || len(to) > maxLen {
// 			return
// 		}

// 		printDiff(from, to)

// 	})
// }

func nl(t *testing.T, lines []string) {
	for i, line := range lines {
		line = strings.TrimSuffix(line, "\n")
		t.Logf("%d: %s \t|| %s", i, line, hex.EncodeToString([]byte(line)))
	}

}

func verifyLineDiff(t *testing.T, ldf LineDiff, from, to []string) {
	var expected string
	if ldf.Operation == LineDel {
		expected = strings.TrimSuffix(from[ldf.LineNumber], "\n")
	} else if ldf.Operation == LineAdd {
		expected = strings.TrimSuffix(to[ldf.LineNumber], "\n")
	} else if ldf.Operation == LineNop {
		expected = strings.TrimSuffix(to[ldf.LineNumber], "\n")
	}

	if ldf.Line != expected {
		t.Fatalf("FAIL ldf: %+v \n---\n(got)'%s' != (expected)'%s'", ldf, ldf.Line, expected)
	}
}

func TestLCSDiff(t *testing.T) {
	from := `
        BEGIN

        AAA

        END
        `
	to := `
        BEGIN

        BBB
        CCC

        NEW
        END
        `

	fromLines := strings.Split(from, "\n")
	t.Log("--- from:")
	nl(t, fromLines)
	toLines := strings.Split(to, "\n")
	t.Log("--- to:")
	nl(t, toLines)
	ldfs := Diff(fromLines, toLines)

	for _, ldf := range ldfs {
		verifyLineDiff(t, ldf, fromLines, toLines)
		t.Log(ldf)
	}

}

func BenchmarkDiff(b *testing.B) {
	from := `
        BEGIN

        AAA

        END
        `
	to := `
        BEGIN

        BBB
        CCC

        NEW
        END
        `

	fromLines := strings.Split(from, "\n")
	toLines := strings.Split(to, "\n")
	for b.Loop() {
		Diff(fromLines, toLines)
	}
}

func FuzzLCSDiff(f *testing.F) {
	f.Fuzz(func(t *testing.T, from, to string) {
		fromLines := strings.Split(from, "\n")
		toLines := strings.Split(to, "\n")

		maxLines := 999999
		if len(fromLines) > maxLines || len(toLines) > maxLines {
			return
		}

		ldfs := Diff(fromLines, toLines)
		if false {
			t.Log("------------")
			t.Log("from: ")
			nl(t, fromLines)
			t.Log("------------")
			t.Log("to: ")
			nl(t, toLines)
			t.Log("------------")
		}
		for _, ldf := range ldfs {
			verifyLineDiff(t, ldf, fromLines, toLines)
		}
	})
}
