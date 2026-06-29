// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pkg

import (
	"encoding/binary"

	cxlrubytes "github.com/cloudxaas/gocache/lru/bytes"
)

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

func (l lcsInput) KeyBytes() []byte {
	var b []byte
	b = binary.BigEndian.AppendUint64(b, uint64(len(l.from)))
	b = binary.BigEndian.AppendUint64(b, uint64(len(l.to)))

	return b
}

type lcsMemoLRU struct {
	cache *cxlrubytes.Cache
}

func (lml *lcsMemoLRU) get(li lcsInput) (int, bool) {
	key := li.KeyBytes()
	valBytes, found := lml.cache.Get(key)
	if !found {
		return 0, false
	}

	val := binary.BigEndian.Uint64(valBytes)

	return int(val), true
}

func (lml *lcsMemoLRU) add(li lcsInput, val int) {
	key := li.KeyBytes()
	b := make([]byte, 8)

	binary.BigEndian.PutUint64(b, uint64(val))

	err := lml.cache.Set(key, b)
	if err != nil {
		panic(err)
	}
}

type lcsMemo struct {
	memo *lcsMemoLRU

	ldfs []LineDiff
}

func newLcsMemo() lcsMemo {
	lm := lcsMemo{
		ldfs: []LineDiff{},
		memo: &lcsMemoLRU{},
	}

	lm.memo.cache = cxlrubytes.NewLRUCache(5*1024*1024*1024, 1024*1024)

	return lm
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
	val, found := l.memo.get(li)
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
		l.memo.add(li, ret-count-1)
	} else {
		ret = max(l.lcs(shaveLast(from), to, count), l.lcs(from, shaveLast(to), count))
		l.memo.add(li, ret-count)
	}

	return ret
}

func lcs(from, to []string) int {
	lm := newLcsMemo()

	return lm.lcs(from, to, 0)
}

func (l *lcsMemo) makeLineDiffs(from, to []string) {
	if len(from) > 0 && len(to) > 0 && lastElem(from) == lastElem(to) {
		l.makeLineDiffs(shaveLast(from), shaveLast(to))
	} else if len(to) > 0 && (len(from) == 0 || l.lcs(from, shaveLast(to), 0) >= l.lcs(shaveLast(from), to, 0)) {
		l.makeLineDiffs(from, shaveLast(to))
		l.ldfs = append(l.ldfs, LineDiff{
			Operation:  LineAdd,
			Line:       lastElem(to),
			LineNumber: uint64(len(to)) - 1,
			TypeOfLine: LineProperty{},
		})
	} else if len(from) > 0 && (len(to) == 0 || l.lcs(from, shaveLast(to), 0) < l.lcs(shaveLast(from), to, 0)) {
		l.makeLineDiffs(shaveLast(from), to)
		l.ldfs = append(l.ldfs, LineDiff{
			Operation:  LineDel,
			Line:       lastElem(from),
			LineNumber: uint64(len(from)) - 1,
			TypeOfLine: LineProperty{},
		})
	}
}

// Diff computes line-level diffs between two string slices using LCS.
func Diff(from, to []string) []LineDiff {
	lm := newLcsMemo()

	lm.makeLineDiffs(from, to)

	return lm.ldfs
}
