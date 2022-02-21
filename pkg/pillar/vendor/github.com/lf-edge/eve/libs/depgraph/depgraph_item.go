// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package depgraph

type singleItemGraph struct {
	itemRef   ItemRef
	path      SubGraphPath // the last known one
	graphRoot Graph
}

// Name returns item reference as string.
func (g *singleItemGraph) Name() string {
	return g.itemRef.String()
}

// Description returns nothing.
func (g *singleItemGraph) Description() string {
	return ""
}

// Item returns either the only item in the graph or nothing.
func (g *singleItemGraph) Item(ref ItemRef) (item Item, state ItemState,
	path SubGraphPath, found bool) {
	if ref == g.itemRef {
		item, state, g.path, found = g.graphRoot.Item(ref)
		return
	}
	return
}

// Items returns a single-item iterator.
func (g *singleItemGraph) Items(_ bool) ItemIterator {
	var items []ItemWithState
	if item, state, path, found := g.graphRoot.Item(g.itemRef); found {
		g.path = path
		items = append(items, ItemWithState{
			Item:  item,
			State: state,
		})
	}
	iter := &itemListIterator{items: items}
	iter.Reset()
	return iter
}

// DiffItems returns list with 0 or 1 item refs.
func (g *singleItemGraph) DiffItems(graph2 GraphR) []ItemRef {
	if graph2 == nil {
		return []ItemRef{g.itemRef}
	}
	g2, ok := graph2.(*singleItemGraph)
	if !ok || g.itemRef != g2.itemRef {
		panic("not supported")
	}
	item1, _, path1, found1 := g.graphRoot.Item(g.itemRef)
	item2, _, path2, found2 := g2.graphRoot.Item(g2.itemRef)
	if found1 != found2 {
		return []ItemRef{g.itemRef}
	}
	if found1 && found2 {
		if !item1.Equal(item2) || path1.Compare(path2) != 0 {
			return []ItemRef{g.itemRef}
		}
	}
	return nil
}

// SubGraph always returns nil.
func (g *singleItemGraph) SubGraph(string) GraphR {
	return nil
}

// SubGraphs returns empty iterator.
func (g *singleItemGraph) SubGraphs() GraphIterator {
	iter := &subGraphIterator{}
	iter.Reset()
	return iter
}

// SubGraph returns a read-only handle to the (direct) parent graph.
func (g *singleItemGraph) ParentGraph() GraphR {
	if _, _, path, found := g.graphRoot.Item(g.itemRef); found {
		g.path = path
		return GetSubGraphR(g.graphRoot, path)
	}
	// Use last known item's location.
	return GetSubGraphR(g.graphRoot, g.path)
}

// ItemAsSubGraph always panics for a single-item graph.
func (g *singleItemGraph) ItemAsSubGraph(ref ItemRef) GraphR {
	panic("not supported")
}

// OutgoingEdges returns iterator for all outgoing edges of the given item,
// as determined by item dependencies.
func (g *singleItemGraph) OutgoingEdges(ref ItemRef) EdgeIterator {
	if ref == g.itemRef {
		return g.graphRoot.OutgoingEdges(ref)
	}
	iter := &edgeIterator{}
	iter.Reset()
	return iter
}

// OutgoingEdges returns iterator for all incoming edges of the given item,
// as determined by dependencies of other items.
func (g *singleItemGraph) IncomingEdges(ref ItemRef) EdgeIterator {
	if ref == g.itemRef {
		return g.graphRoot.IncomingEdges(ref)
	}
	iter := &edgeIterator{}
	iter.Reset()
	return iter
}

// DetectCycle returns no cycle.
func (g *singleItemGraph) DetectCycle() []ItemRef {
	return nil
}

// PrivateData returns nil.
func (g *singleItemGraph) PrivateData() interface{} {
	return nil
}

// SetDescription panics if called with non-empty description.
func (g *singleItemGraph) SetDescription(description string) {
	if description != "" {
		panic("not supported")
	}
}

// PutItem adds/updates the item.
func (g *singleItemGraph) PutItem(item Item, state ItemState) {
	if g.itemRef != Reference(item) {
		panic("not supported")
	}
	parent := g.EditParentGraph()
	parent.PutItem(item, state)
}

// DelItem deletes the item.
// Returns true if the item existed and was actually deleted.
func (g *singleItemGraph) DelItem(ref ItemRef) bool {
	if g.itemRef != ref {
		panic("not supported")
	}
	parent := g.EditParentGraph()
	return parent.DelItem(ref)
}

// PutSubGraph always panics for a single-item graph.
func (g *singleItemGraph) PutSubGraph(Graph) {
	panic("not supported")
}

// DelSubGraph always panics for a single-item graph.
func (g *singleItemGraph) DelSubGraph(name string) bool {
	panic("not supported")
}

// EditSubGraph always panics for a single-item graph.
func (g *singleItemGraph) EditSubGraph(GraphR) Graph {
	panic("not supported")
}

// EditParentGraph returns read-write handle to the (direct) parent graph.
func (g *singleItemGraph) EditParentGraph() Graph {
	if _, _, path, found := g.graphRoot.Item(g.itemRef); found {
		g.path = path
		return GetSubGraph(g.graphRoot, path)
	}
	// Use last known item's location.
	return GetSubGraph(g.graphRoot, g.path)
}

// PutPrivateData always panics for a single-item graph.
func (g *singleItemGraph) PutPrivateData(privateData interface{}) {
	panic("not supported")
}