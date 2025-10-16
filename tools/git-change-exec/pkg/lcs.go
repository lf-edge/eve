// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pkg

func max(a, b int) int {
	if a > b {
		return a
	}

	return b
}

func shaveLast(str []string) []string {
	if len(str) == 0 {
		return str
	}

	return str[:len(str)-1]
}

func lastElem(str []string) string {
	return str[len(str)-1]
}

type lcsInput struct {
	from []string
	to   []string
}

func (l lcsInput) Key() [2]int {
	return [2]int{len(l.from), len(l.to)}
}

type lcsMemo struct {
	memo map[[2]int]int

	ldfs []LineDiff
}

func (l *lcsMemo) lcs(from, to []string, count int) int {
	if len(from) == 0 {
		return count
	}
	if len(to) == 0 {
		return count
	}

	li := lcsInput{
		from: from,
		to:   to,
	}
	memoKey := li.Key()
	val, found := l.memo[memoKey]
	if found {
		return val + count
	}

	var ret int
	if lastElem(from) == lastElem(to) {
		ret = l.lcs(shaveLast(from), shaveLast(to), count+1)
		li := lcsInput{
			from: shaveLast(from),
			to:   shaveLast(to),
		}
		l.memo[li.Key()] = ret - count - 1
	} else {
		ret = max(l.lcs(shaveLast(from), to, count), l.lcs(from, shaveLast(to), count))
		l.memo[li.Key()] = ret - count
	}

	return ret
}

func lcs(from, to []string) int {
	lm := lcsMemo{
		memo: map[[2]int]int{},
	}

	return lm.lcs(from, to, 0)
}

func (l *lcsMemo) printDiff(from, to []string) {
	if len(from) > 0 && len(to) > 0 && lastElem(from) == lastElem(to) {
		l.printDiff(shaveLast(from), shaveLast(to))
		// fmt.Printf("  %s\n", lastElem(from))
	} else if len(to) > 0 && (len(from) == 0 || l.lcs(from, shaveLast(to), 0) >= l.lcs(shaveLast(from), to, 0)) {
		l.printDiff(from, shaveLast(to))
		// fmt.Printf("+ %s\n", lastElem(to))
		l.ldfs = append(l.ldfs, LineDiff{
			Operation:  LineAdd,
			Line:       lastElem(to),
			LineNumber: uint64(len(to)) - 1,
			TypeOfLine: LineProperty{},
		})
	} else if len(from) > 0 && (len(to) == 0 || l.lcs(from, shaveLast(to), 0) < l.lcs(shaveLast(from), to, 0)) {
		l.printDiff(shaveLast(from), to)
		// fmt.Printf("- %s\n", lastElem(from))
		l.ldfs = append(l.ldfs, LineDiff{
			Operation:  LineDel,
			Line:       lastElem(from),
			LineNumber: uint64(len(from)) - 1,
			TypeOfLine: LineProperty{},
		})
	}
}

func Diff(from, to []string) []LineDiff {
	lm := lcsMemo{
		memo: map[[2]int]int{},
		ldfs: []LineDiff{},
	}

	lm.printDiff(from, to)

	return lm.ldfs
}
