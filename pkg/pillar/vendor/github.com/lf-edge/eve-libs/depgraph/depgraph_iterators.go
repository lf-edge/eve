// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package depgraph

type itemIterator struct {
	graph      *graph
	curIdx     int
	begin, end int // [begin, end)
}

type itemListIterator struct {
	items  []ItemWithState
	curIdx int
}

type subGraphIterator struct {
	// graph can be nil, then it returns empty content.
	graph  *graph
	curIdx int
}

type edgeIterator struct {
	edges  edges
	curIdx int
}

// Item returns the current Item from the iterator.
func (iter *itemIterator) Item() (Item, ItemState) {
	totalLen := iter.end - iter.begin
	if iter.curIdx >= totalLen {
		return nil, nil
	}
	node := iter.graph.sortedNodes[iter.begin+iter.curIdx]
	return node.item, node.state
}

// Next advances the iterator and returns whether the next call
// to the Item() method will return non-nil values.
func (iter *itemIterator) Next() bool {
	iter.curIdx++
	totalLen := iter.end - iter.begin
	return iter.curIdx < totalLen
}

// Len returns the number of items remaining in the iterator.
func (iter *itemIterator) Len() int {
	totalLen := iter.end - iter.begin
	if iter.curIdx >= totalLen {
		return 0
	}
	return totalLen - (iter.curIdx + 1)
}

// Reset returns the iterator to its start position.
func (iter *itemIterator) Reset() {
	iter.curIdx = -1
}

// Item returns the current Item from the iterator.
func (iter *itemListIterator) Item() (Item, ItemState) {
	if iter.curIdx >= len(iter.items) {
		return nil, nil
	}
	iws := iter.items[iter.curIdx]
	return iws.Item, iws.State
}

// Next advances the iterator and returns whether the next call
// to the Item() method will return non-nil values.
func (iter *itemListIterator) Next() bool {
	iter.curIdx++
	return iter.curIdx < len(iter.items)
}

// Len returns the number of items remaining in the iterator.
func (iter *itemListIterator) Len() int {
	if iter.curIdx >= len(iter.items) {
		return 0
	}
	return len(iter.items) - (iter.curIdx + 1)
}

// Reset returns the iterator to its start position.
func (iter *itemListIterator) Reset() {
	iter.curIdx = -1
}

// SubGraph returns the current subgraph from the iterator.
func (iter *subGraphIterator) SubGraph() GraphR {
	if iter.graph == nil {
		return nil
	}
	if iter.curIdx >= len(iter.graph.subgraphs) {
		return nil
	}
	return iter.graph.subgraphs[iter.curIdx]
}

// Next advances the iterator and returns whether the next call
// to the SubGraph() method will return a non-nil value.
func (iter *subGraphIterator) Next() bool {
	if iter.graph == nil {
		return false
	}
	iter.curIdx++
	return iter.curIdx < len(iter.graph.subgraphs)
}

// Len returns the number of subgraphs remaining in the iterator.
func (iter *subGraphIterator) Len() int {
	if iter.graph == nil {
		return 0
	}
	if iter.curIdx >= len(iter.graph.subgraphs) {
		return 0
	}
	return len(iter.graph.subgraphs) - (iter.curIdx + 1)
}

// Reset returns the iterator to its start position.
func (iter *subGraphIterator) Reset() {
	iter.curIdx = -1
}

// Edge returns the current Edge from the iterator.
func (iter *edgeIterator) Edge() Edge {
	if iter.curIdx >= len(iter.edges) {
		return Edge{}
	}
	return *iter.edges[iter.curIdx]
}

// Next advances the iterator and returns whether the next call
// to the Edge() method will return a non-nil value.
func (iter *edgeIterator) Next() bool {
	iter.curIdx++
	return iter.curIdx < len(iter.edges)
}

// Len returns the number of edges remaining in the iterator.
func (iter *edgeIterator) Len() int {
	if iter.curIdx >= len(iter.edges) {
		return 0
	}
	return len(iter.edges) - (iter.curIdx + 1)
}

// Reset returns the iterator to its start position.
func (iter *edgeIterator) Reset() {
	iter.curIdx = -1
}
