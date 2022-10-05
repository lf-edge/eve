// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package depgraph

import (
	"fmt"
	"sort"
)

// graph implements Graph interface.
type graph struct {
	name        string
	description string

	parent       *graph
	root         *graph
	pathFromRoot SubGraphPath
	subgraphs    graphs

	nodes map[ItemRef]*node
	// Nodes sorted lexicographically by subgraph, then by item reference.
	sortedNodes []*node

	outgoingEdges map[ItemRef]edges
	incomingEdges map[ItemRef]edges

	privateData interface{}
}

type node struct {
	item      Item
	state     ItemState
	graphRoot Graph
	path      SubGraphPath
}

func (n *node) itemRef() ItemRef {
	return ItemRef{
		ItemType: n.item.Type(),
		ItemName: n.item.Name(),
	}
}

type edges []*Edge

func removeEdge(edges edges, edgeIndex int) edges {
	edges[edgeIndex] = edges[len(edges)-1]
	edges[len(edges)-1] = nil
	edges = edges[:len(edges)-1]
	return edges
}

type graphs []*graph

func removeGraph(graphs graphs, graphIndex int) graphs {
	graphs[graphIndex] = graphs[len(graphs)-1]
	graphs[len(graphs)-1] = nil
	graphs = graphs[:len(graphs)-1]
	return graphs
}

// New creates a new instance of the dependency graph.
func New(args InitArgs) Graph {
	g := &graph{
		name:        args.Name,
		description: args.Description,
		privateData: args.PrivateData,
	}
	g.reset()
	g.root = g
	for _, item := range args.Items {
		g.PutItem(item, nil)
	}
	for _, iws := range args.ItemsWithState {
		g.PutItem(iws.Item, iws.State)
	}
	for _, subGraph := range args.Subgraphs {
		g.PutSubGraph(New(subGraph))
	}
	return g
}

func (g *graph) reset() {
	g.nodes = make(map[ItemRef]*node)
	g.outgoingEdges = make(map[ItemRef]edges)
	g.incomingEdges = make(map[ItemRef]edges)
	g.sortedNodes = []*node{}
}

// Name assigned to the (sub)graph.
func (g *graph) Name() string {
	return g.name
}

// Description assigned to the (sub)graph.
func (g *graph) Description() string {
	return g.description
}

// Item returns an item from the graph, incl. state data stored alongside it.
// The function will look for the item also inside all the subgraphs.
func (g *graph) Item(ref ItemRef) (item Item, state ItemState, path SubGraphPath, found bool) {
	node, exists := g.root.nodes[ref]
	if !exists || !g.pathFromRoot.IsPrefixOf(node.path) {
		return nil, nil, SubGraphPath{}, false
	}
	return node.item, node.state, node.path.TrimPrefix(g.pathFromRoot), true
}

// Returns range [i,j) inside g.sortedNodes where nodes of the given subgraph
// are located.
func (g *graph) findNodeRange(subGraph SubGraphPath, inclNested bool) (
	first, firstAfter int) {
	first = sort.Search(len(g.sortedNodes), func(i int) bool {
		node := g.sortedNodes[i]
		pathCmp := subGraph.Compare(node.path)
		return pathCmp == 0 || pathCmp == -1
	})
	firstAfter = sort.Search(len(g.sortedNodes), func(i int) bool {
		node := g.sortedNodes[i]
		pathCmp := subGraph.Compare(node.path)
		if inclNested {
			return pathCmp == -1 && !subGraph.IsPrefixOf(node.path)
		}
		return pathCmp == -1
	})
	return
}

// Items returns an iterator for items inside this graph.
// If inclSubGraphs is set to true, the iteration will include items
// from subgraphs (both direct and nested).
func (g *graph) Items(inclSubGraphs bool) ItemIterator {
	iter := &itemIterator{
		graph: g.root,
	}
	iter.begin, iter.end = g.root.findNodeRange(g.pathFromRoot, inclSubGraphs)
	iter.Reset()
	return iter
}

// DiffItems returns references to items that differ between this and the other graph.
func (g *graph) DiffItems(graph2 GraphR) (diff []ItemRef) {
	if graph2 == nil {
		begin, end := g.root.findNodeRange(g.pathFromRoot, true)
		for i := begin; i < end; i++ {
			node := g.root.sortedNodes[i]
			diff = append(diff, node.itemRef())
		}
		return
	}
	g2, ok := graph2.(*graph)
	if !ok {
		panic("argument is not an instance of graph")
	}
	begin1, end1 := g.root.findNodeRange(g.pathFromRoot, true)
	begin2, end2 := g2.root.findNodeRange(g2.pathFromRoot, true)
	diffMap := make(map[ItemRef]struct{})
	i := begin1
	j := begin2
	for i < end1 && j < end2 {
		n1 := g.root.sortedNodes[i]
		n2 := g2.root.sortedNodes[j]
		// Compare relative paths (w.r.t. g and g2), not absolute paths.
		n1Path := n1.path.TrimPrefix(g.pathFromRoot)
		n2Path := n2.path.TrimPrefix(g2.pathFromRoot)
		pathCmp := n1Path.Compare(n2Path)
		idCmp := n1.itemRef().Compare(n2.itemRef())
		if pathCmp == -1 || (pathCmp == 0 && idCmp == -1) {
			diffMap[n1.itemRef()] = struct{}{}
			i++
			continue
		}
		if pathCmp == 1 || (pathCmp == 0 && idCmp == 1) {
			diffMap[n2.itemRef()] = struct{}{}
			j++
			continue
		}
		itemEqual := n1.item.Equal(n2.item)
		if !itemEqual {
			diffMap[n1.itemRef()] = struct{}{}
		}
		i++
		j++
	}
	for ; i < end1; i++ {
		diffMap[g.root.sortedNodes[i].itemRef()] = struct{}{}
	}
	for ; j < end2; j++ {
		diffMap[g2.root.sortedNodes[j].itemRef()] = struct{}{}
	}
	for itemRef := range diffMap {
		diff = append(diff, itemRef)
	}
	return diff
}

// SubGraph returns a read-only handle to a (direct, not nested) subgraph.
// Returns nil if subgraph with such name is not present.
func (g *graph) SubGraph(name string) GraphR {
	for _, subGraph := range g.subgraphs {
		if subGraph.name == name {
			return subGraph
		}
	}
	return nil
}

// SubGraphs returns an iterator for (direct) subgraphs of this graph.
func (g *graph) SubGraphs() GraphIterator {
	iter := &subGraphIterator{graph: g}
	iter.Reset()
	return iter
}

// SubGraph returns a read-only handle to the (direct) parent graph.
// Returns nil if the graph is not a subgraph.
func (g *graph) ParentGraph() GraphR {
	if g.parent == nil {
		return nil
	}
	return g.parent
}

// ItemAsSubGraph allows to view an item (that may or may not exist)
// as a single-item subgraph.
// This is useful if you need a common interface for a subgraph and an item.
func (g *graph) ItemAsSubGraph(ref ItemRef) GraphR {
	return &singleItemGraph{
		itemRef:   ref,
		path:      g.pathFromRoot,
		graphRoot: g.root,
	}
}

// OutgoingEdges returns iterator for all outgoing edges of the given item,
// as determined by item dependencies.
// Item can be also from a subgraph (direct or nested).
func (g *graph) OutgoingEdges(ref ItemRef) EdgeIterator {
	node, exists := g.root.nodes[ref]
	var edges edges
	if exists && g.pathFromRoot.IsPrefixOf(node.path) {
		edges = g.root.outgoingEdges[ref]
	}
	iter := &edgeIterator{edges: edges}
	iter.Reset()
	return iter
}

// IncomingEdges returns iterator for all incoming edges of the given item,
// as determined by dependencies of other items.
// Item can be also from a subgraph (direct or nested).
func (g *graph) IncomingEdges(ref ItemRef) EdgeIterator {
	node, exists := g.root.nodes[ref]
	var edges edges
	if exists && g.pathFromRoot.IsPrefixOf(node.path) {
		edges = g.root.incomingEdges[ref]
	}
	iter := &edgeIterator{edges: edges}
	iter.Reset()
	return iter
}

// detectCycle is based on DFS with recursion.
// stack : item ref -> stack index
func (g *graph) detectCycle(itemRef ItemRef, visited map[ItemRef]struct{},
	stack map[ItemRef]int) (cycle []ItemRef) {
	if _, alreadyVisited := visited[itemRef]; alreadyVisited {
		return nil
	}

	// pre-order
	stack[itemRef] = len(stack)
	for _, edge := range g.outgoingEdges[itemRef] {
		adjItem := edge.ToItem
		if adjIdx, inStack := stack[adjItem]; inStack {
			// Cycle detected!
			for id, idx := range stack {
				if idx >= adjIdx {
					cycle = append(cycle, id)
				}
			}
			sort.Slice(cycle, func(i, j int) bool {
				return stack[cycle[i]] < stack[cycle[j]]
			})
			return cycle
		}
		cycle := g.detectCycle(adjItem, visited, stack)
		if len(cycle) > 0 {
			return cycle
		}
	}

	// post-order
	delete(stack, itemRef)
	visited[itemRef] = struct{}{}
	return nil
}

// DetectCycle checks if the graph contains a cycle (which it should not,
// dependency graph is supposed to be DAG) and the first one found is returned
// as a list of references to items inside the cycle.
func (g *graph) DetectCycle() []ItemRef {
	visited := make(map[ItemRef]struct{})
	stack := make(map[ItemRef]int)
	for _, node := range g.nodes {
		cycle := g.detectCycle(node.itemRef(), visited, stack)
		if len(cycle) > 0 {
			return cycle
		}
		if len(stack) != 0 {
			panic("unexpectedly non-empty stack")
		}
	}
	return nil
}

// PrivateData returns whatever custom data has the user stored with the graph.
func (g *graph) PrivateData() interface{} {
	return g.privateData
}

// SetDescription updates description assigned to the (sub)graph.
func (g *graph) SetDescription(description string) {
	g.description = description
}

// Return index in the array g.sortedNodes at which the given node should be.
// Note that g.sortedNodes is ordered lexicographically first by subgraph path,
// then by item reference.
func (g *graph) findNodeIndex(node *node) (index int) {
	return sort.Search(len(g.sortedNodes), func(i int) bool {
		node2 := g.sortedNodes[i]
		pathCmp := node.path.Compare(node2.path)
		idCmp := node.itemRef().Compare(node2.itemRef())
		return (pathCmp == 0 && idCmp == 0) ||
			(pathCmp == 0 && idCmp == -1) ||
			pathCmp == -1
	})
}

func (g *graph) putNode(node *node) {
	// Check item and dependencies first.
	if node.item == nil {
		panic("missing item inside node")
	}
	deps := node.item.Dependencies()
	if node.item.External() && len(deps) > 0 {
		panic(fmt.Sprintf("External item %v should not have dependencies",
			node.itemRef()))
	}
	validateDeps(deps)

	// Update or add the node.
	nodeIndex := g.findNodeIndex(node)
	if origNode, exists := g.nodes[node.itemRef()]; exists {
		itemEquals := origNode.item.Equal(node.item)
		origNodeIndex := g.findNodeIndex(origNode)
		*origNode = *node
		if nodeIndex != origNodeIndex {
			// move inside g.sortedNodes
			if nodeIndex < origNodeIndex {
				copy(g.sortedNodes[nodeIndex+1:origNodeIndex+1],
					g.sortedNodes[nodeIndex:origNodeIndex])
				g.sortedNodes[nodeIndex] = origNode
			} else {
				copy(g.sortedNodes[origNodeIndex:nodeIndex-1],
					g.sortedNodes[origNodeIndex+1:nodeIndex])
				g.sortedNodes[nodeIndex-1] = origNode
			}
		}
		if !itemEquals {
			g.updateEdges(node.itemRef(), deps)
		}
		return
	}

	// Add new node.
	g.nodes[node.itemRef()] = node
	g.sortedNodes = append(g.sortedNodes, nil)
	if nodeIndex < len(g.sortedNodes)-1 {
		copy(g.sortedNodes[nodeIndex+1:], g.sortedNodes[nodeIndex:])
	}
	g.sortedNodes[nodeIndex] = node
	// add edge for every dependency
	if len(g.outgoingEdges[node.itemRef()]) > 0 {
		panic(fmt.Sprintf("item %s already has some outgoing edges", node.itemRef()))
	}
	for _, dep := range deps {
		g.addNewEdge(node.itemRef(), dep)
	}
}

func (g *graph) updateEdges(fromItem ItemRef, newDeps []Dependency) {
	_, exists := g.nodes[fromItem]
	if !exists {
		panic(fmt.Sprintf("item %s is not present in the graph", fromItem))
	}
	// Remove obsolete edges and update existing ones.
	edges := g.outgoingEdges[fromItem]
	for i := 0; i < len(edges); {
		var found bool
		edge := edges[i]
		for _, newDep := range newDeps {
			if edge.Dependency.RequiredItem == newDep.RequiredItem {
				edge.Dependency = newDep
				found = true
				break
			}
		}
		if !found {
			edges = removeEdge(edges, i)
			g.removeIncomingEdge(edge)
		} else {
			i++
		}
	}
	g.outgoingEdges[fromItem] = edges
	// Add new edges.
	for _, newDep := range newDeps {
		var found bool
		for _, edge := range edges {
			if edge.Dependency.RequiredItem == newDep.RequiredItem {
				found = true
				break
			}
		}
		if !found {
			g.addNewEdge(fromItem, newDep)
		}
	}
}

func (g *graph) addNewEdge(fromItem ItemRef, dep Dependency) {
	edge := &Edge{
		FromItem:   fromItem,
		ToItem:     dep.RequiredItem,
		Dependency: dep,
	}
	g.outgoingEdges[fromItem] = append(
		g.outgoingEdges[fromItem], edge)
	g.incomingEdges[edge.ToItem] = append(
		g.incomingEdges[edge.ToItem], edge)
}

func (g *graph) removeIncomingEdge(edge *Edge) {
	for i, inEdge := range g.incomingEdges[edge.ToItem] {
		// compare pointers
		if inEdge == edge {
			g.incomingEdges[edge.ToItem] = removeEdge(
				g.incomingEdges[edge.ToItem], i)
			return
		}
	}
}

// PutItem adds or moves (and updates) item into this (sub)graph.
// Function also adds or updates ItemState stored alongside the item.
func (g *graph) PutItem(item Item, state ItemState) {
	node := &node{
		item:      item,
		state:     state,
		graphRoot: g.root,
		path:      g.pathFromRoot,
	}
	g.root.putNode(node)
}

func (g *graph) delNode(ref ItemRef, path SubGraphPath) bool {
	node, exists := g.nodes[ref]
	if !exists || node.path.Compare(path) != 0 {
		return false
	}
	// remove from graph.nodes
	delete(g.nodes, ref)
	// remove from graph.sortedNodes
	nodeIndex := g.findNodeIndex(node)
	if nodeIndex >= len(g.sortedNodes) ||
		g.sortedNodes[nodeIndex].itemRef().Compare(ref) != 0 {
		panic(fmt.Sprintf("item %s is not present in graph.sortedNodes",
			ref))
	}
	if nodeIndex < len(g.sortedNodes)-1 {
		copy(g.sortedNodes[nodeIndex:], g.sortedNodes[nodeIndex+1:])
	}
	g.sortedNodes[len(g.sortedNodes)-1] = nil
	g.sortedNodes = g.sortedNodes[:len(g.sortedNodes)-1]
	// remove all outgoing edges (but keep incoming for this node)
	for _, edge := range g.outgoingEdges[ref] {
		// remove it from incomingEdges of the opposite node
		g.removeIncomingEdge(edge)
	}
	delete(g.outgoingEdges, ref)
	return true
}

// DelItem deletes an existing item from this (sub)graph.
// Returns true if the item existed and was actually deleted.
func (g *graph) DelItem(ref ItemRef) bool {
	return g.root.delNode(ref, g.pathFromRoot)
}

func setRoot(graph, root *graph, pathFromRoot SubGraphPath) {
	graph.root = root
	graph.pathFromRoot = pathFromRoot
	for _, subG := range graph.subgraphs {
		setRoot(subG, root, pathFromRoot.Append(subG.name))
	}
}

func (g *graph) findSubgraph(name string) (idx int) {
	for idx = 0; idx < len(g.subgraphs); idx++ {
		if g.subgraphs[idx].name == name {
			break
		}
	}
	return idx
}

// PutSubGraph adds a new subgraph into this graph or updates an existing
// subgraph. This refers to a direct child of this graph, cannot add/update
// a nested subgraphs.
func (g *graph) PutSubGraph(subGraph Graph) {
	subG, ok := subGraph.(*graph)
	if !ok {
		panic("subGraph is not an instance of graph")
	}
	if subG.root != subG {
		panic("subGraph is already attached to a graph")
	}

	idx := g.findSubgraph(subG.name)
	if idx < len(g.subgraphs) {
		// Update existing.
		// For now we do this by simply deleting the previous one first.
		g.DelSubGraph(subG.name)
	}

	// Add new subgraph.
	subGraphPath := g.pathFromRoot.Append(subG.name)
	setRoot(subG, g.root, subGraphPath)
	subG.parent = g
	g.subgraphs = append(g.subgraphs, subG)

	// Put all nodes under the root.
	for _, node := range subG.sortedNodes {
		node.graphRoot = g.root
		node.path = subGraphPath.Concatenate(node.path)
		g.root.putNode(node)
	}

	// Everything was moved up to the root.
	subG.reset()
}

// DelSubGraph deletes existing subgraph. This refers to a direct child of this
// graph, cannot delete a nested subgraph.
// Returns true if the subgraph existed and was actually deleted.
// It is an error to try to use a subgraph after it was deleted (can't be used
// even as a separate graph anymore).
func (g *graph) DelSubGraph(name string) bool {
	// Remove pointer the the subgraph.
	idx := g.findSubgraph(name)
	if idx == len(g.subgraphs) {
		return false
	}
	subG := g.subgraphs[idx]
	g.subgraphs = removeGraph(g.subgraphs, idx)
	// Remove nodes.
	root := g.root
	first, firstAfter := root.findNodeRange(subG.pathFromRoot, true)
	count := firstAfter - first
	for i := first; i < firstAfter; i++ {
		node := root.sortedNodes[i]
		delete(root.nodes, node.itemRef())
		// remove all outgoing edges (but keep incoming for this node)
		for _, edge := range root.outgoingEdges[node.itemRef()] {
			// remove it from incomingEdges of the opposite node
			root.removeIncomingEdge(edge)
		}
		delete(root.outgoingEdges, node.itemRef())
	}
	copy(root.sortedNodes[first:], root.sortedNodes[firstAfter:])
	for i := 0; i < count; i++ {
		root.sortedNodes[len(root.sortedNodes)-1-i] = nil
	}
	root.sortedNodes = root.sortedNodes[:len(root.sortedNodes)-count]
	// Note: it would be a bug to continue using the subgraph.
	subG.parent = nil
	subG.root = nil
	return true
}

// EditSubGraph elevates read-only subgraph handle to read-write access.
// Panics if the given graph is not actually a subgraph (direct or nested)
// of this graph.
func (g *graph) EditSubGraph(subGraph GraphR) Graph {
	if singleNodeG, ok := subGraph.(*singleItemGraph); ok {
		if g.root == singleNodeG.graphRoot {
			return singleNodeG
		}
	} else {
		subG := subGraph.(*graph)
		if g.root == subG.root {
			if g.pathFromRoot.IsPrefixOf(subG.pathFromRoot) {
				return subG
			}
		}
	}
	panic(fmt.Sprintf("Graph %s does not contain sub-graph %s",
		g.name, subGraph.Name()))
}

// EditParentGraph returns read-write handle to a (direct) parent graph
// of this subgraph.
// Return nil if the graph is not a subgraph.
func (g *graph) EditParentGraph() Graph {
	if g.parent == nil {
		return nil
	}
	return g.parent
}

// PutPrivateData allows the user to store any data with the graph.
func (g *graph) PutPrivateData(privateData interface{}) {
	g.privateData = privateData
}

// Multiple dependencies pointing to the same item are not allowed.
func validateDeps(deps []Dependency) {
	for i := 0; i < len(deps); i++ {
		for j := i + 1; j < len(deps); j++ {
			if deps[i].RequiredItem == deps[j].RequiredItem {
				// Strictly speaking this is a programming error,
				// so let's just lazily put panic in here.
				panic(fmt.Sprintf("Duplicate dependencies (required item: %s)",
					deps[i].RequiredItem))
			}
		}
	}
}
