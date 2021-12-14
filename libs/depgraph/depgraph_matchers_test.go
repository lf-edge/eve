// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package depgraph_test

import (
	"fmt"
	"reflect"

	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"

	. "github.com/lf-edge/eve/libs/depgraph"
)


// ContainItem checks if iterated list of items includes the given item.
func ContainItem(item mockItem) types.GomegaMatcher {
	return &mockItemMatcher{
		expItem:  item,
		expState: nil,
	}
}

// ContainItemWithState checks if iterated list of items includes the given item.
func ContainItemWithState(item mockItem, state ItemState) types.GomegaMatcher {
	return &mockItemMatcher{
		expItem:  item,
		expState: state,
	}
}

// mockItemMatcher implements types.GomegaMatcher.
type mockItemMatcher struct {
	expItem  mockItem
	expState ItemState
}

func (m *mockItemMatcher) Match(actual interface{}) (success bool, err error) {
	switch items := actual.(type) {
	case ItemIterator:
		return m.matchIter(items)
	case []ItemRef:
		return m.matchSliceWithRefs(items)
	case []mockItem:
		return m.matchSliceWithItems(items)
	default:
		return false, fmt.Errorf("mockItemMatcher expects an item iterator "+
			"or a slice with items or at least with their references")
	}
}

func (m *mockItemMatcher) matchIter(iter ItemIterator) (success bool, err error) {
	iter.Reset()
	defer iter.Reset()
	for iter.Next() {
		item, state := iter.Item()
		mockItem := item.(mockItem)
		if Reference(mockItem) == Reference(m.expItem) {
			return reflect.DeepEqual(mockItem.attrs, m.expItem.attrs) &&
					state == m.expState,
				nil
		}
	}
	return false, nil
}

func (m *mockItemMatcher) matchSliceWithRefs(itemRefs []ItemRef) (success bool, err error) {
	for _, itemRef := range itemRefs {
		if itemRef == Reference(m.expItem) {
			return true, nil
		}
	}
	return false, nil
}

func (m *mockItemMatcher) matchSliceWithItems(items []mockItem) (success bool, err error) {
	for _, item := range items {
		if Reference(item) == Reference(m.expItem) {
			return reflect.DeepEqual(item.attrs, m.expItem.attrs), nil
		}
	}
	return false, nil
}

func (m *mockItemMatcher) FailureMessage(interface{}) (message string) {
	return fmt.Sprintf("Expected the set to contain mock item\n%s",
		format.Object(m.expItem, 1))
}

func (m *mockItemMatcher) NegatedFailureMessage(interface{}) (message string) {
	return fmt.Sprintf("Expected the set to NOT contain mock item\n%s",
		format.Object(m.expItem, 1))
}

// ContainEdge checks if iterated list of edges includes the given edge.
func ContainEdge(fromItem, toItem ItemRef) types.GomegaMatcher {
	return &edgeMatcher{
		expFromItem: fromItem,
		expToItem:   toItem,
	}
}

// edgeMatcher implements types.GomegaMatcher.
type edgeMatcher struct {
	expFromItem ItemRef
	expToItem   ItemRef
}

func (m *edgeMatcher) Match(actual interface{}) (success bool, err error) {
	iter, ok := actual.(EdgeIterator)
	if !ok {
		return false, fmt.Errorf("edgeMatcher expects an edge iterator")
	}
	iter.Reset()
	defer iter.Reset()
	for iter.Next() {
		edge := iter.Edge()
		if edge.FromItem == m.expFromItem && edge.ToItem == m.expToItem {
			return true, nil
		}
	}
	return false, nil
}

func (m *edgeMatcher) FailureMessage(interface{}) (message string) {
	return fmt.Sprintf("Expected the iterated set to contain edge %s->%s",
		m.expFromItem, m.expToItem)
}

func (m *edgeMatcher) NegatedFailureMessage(interface{}) (message string) {
	return fmt.Sprintf("Expected the iterated set to NOT contain edge %s->%s",
		m.expFromItem, m.expToItem)
}

// ContainSubGraph checks if iterated list of subgraphs includes the given subgraph.
func ContainSubGraph(name string) types.GomegaMatcher {
	return &subGraphMatcher{
		expName: name,
	}
}

// subGraphMatcher implements types.GomegaMatcher.
type subGraphMatcher struct {
	expName string
}

func (m *subGraphMatcher) Match(actual interface{}) (success bool, err error) {
	iter, ok := actual.(GraphIterator)
	if !ok {
		return false, fmt.Errorf("subGraphMatcher expects a subGraph iterator")
	}
	iter.Reset()
	defer iter.Reset()
	for iter.Next() {
		subG := iter.SubGraph()
		if subG.Name() == m.expName {
			return true, nil
		}
	}
	return false, nil
}

func (m *subGraphMatcher) FailureMessage(interface{}) (message string) {
	return fmt.Sprintf("Expected the iterated set to contain subGraph %s",
		m.expName)
}

func (m *subGraphMatcher) NegatedFailureMessage(interface{}) (message string) {
	return fmt.Sprintf("Expected the iterated set to NOT contain subgraph %s",
		m.expName)
}
