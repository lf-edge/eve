// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package depgraph

// Graph is a dependency graph.
// The main use-case is to represent configuration items (network interfaces, routes,
// volumes, etc.) or any managed stateful objects (incl. processes, containers, files,
// etc.) as graph nodes (here called items instead) and their dependencies as directed
// graph edges.
// For more information please see README.md.
type Graph interface {
	GraphR

	// SetDescription updates description assigned to the (sub)graph.
	SetDescription(string)

	// PutItem adds or moves (and updates) item into this (sub)graph.
	// Function also adds or updates ItemState stored alongside the item.
	PutItem(item Item, state ItemState)
	// DelItem deletes an existing item from this (sub)graph.
	// Returns true if the item existed and was actually deleted.
	DelItem(ItemRef) bool

	// PutSubGraph adds a new subgraph into this graph or updates an existing
	// subgraph. This refers to a direct child of this graph, cannot add/update
	// a nested subgraphs.
	PutSubGraph(Graph)
	// DelSubGraph deletes existing subgraph. This refers to a direct child of this
	// graph, cannot delete a nested subgraph.
	// Returns true if the subgraph existed and was actually deleted.
	// It is an error to try to use a subgraph after it was deleted (can't be used
	// even as a separate graph anymore).
	DelSubGraph(name string) bool
	// EditSubGraph elevates read-only subgraph handle to read-write access.
	// Panics if the given graph is not actually a subgraph (direct or nested)
	// of this graph.
	EditSubGraph(GraphR) Graph
	// EditParentGraph returns read-write handle to a (direct) parent graph
	// of this subgraph.
	// Return nil if the graph is not a subgraph.
	EditParentGraph() Graph

	// PutPrivateData allows the user to store any data with the graph.
	// Graph does not do anything with these data.
	// Retrieve with GraphR.PrivateData().
	PutPrivateData(interface{})
}

// GraphR : Read-only access to a dependency graph.
type GraphR interface {
	// Name assigned to the (sub)graph.
	Name() string
	// Description assigned to the (sub)graph.
	Description() string

	// Item returns an item from the graph, incl. state data stored alongside it.
	// The function will look for the item also inside all the subgraphs
	// (both direct and nested). If found, it will also return a path leading
	// to the subgraph with the item.
	// To obtain reference to the subgraph, use GetSubGraph().
	Item(ItemRef) (item Item, state ItemState, path SubGraphPath, found bool)
	// Items returns an iterator for items inside this graph.
	// If inclSubGraphs is set to true, the iteration will include items
	// from subgraphs (both direct and nested).
	Items(inclSubGraphs bool) ItemIterator
	// DiffItems returns references to items that differ between this and the other
	// graph. Two respective item instances are considered different if Item.Equal(other)
	// returns false, or if their location wrt. subgraphs is different.
	// Item state data are not compared.
	// A returned reference may refer to an item present in this graph but not present
	// in the other graph and vice versa.
	// otherGraph is allowed to be nil - in that case references to all items in this
	// graph will be returned.
	// Complexity is O(V).
	DiffItems(otherGraph GraphR) []ItemRef

	// SubGraph returns a read-only handle to a (direct, not nested) subgraph.
	// Returns nil if subgraph with such name is not present.
	SubGraph(name string) GraphR
	// SubGraphs returns an iterator for (direct) subgraphs of this graph.
	SubGraphs() GraphIterator
	// SubGraph returns a read-only handle to the (direct) parent graph.
	// Return nil if the graph is not a subgraph.
	ParentGraph() GraphR
	// ItemAsSubGraph allows to view an item (that may or may not exist)
	// as a single-item subgraph.
	// This is useful if you need a common interface for a subgraph and an item.
	ItemAsSubGraph(ItemRef) GraphR

	// OutgoingEdges returns iterator for all outgoing edges of the given item,
	// as determined by item dependencies.
	// Item can be also from a subgraph (direct or nested).
	OutgoingEdges(ItemRef) EdgeIterator
	// OutgoingEdges returns iterator for all incoming edges of the given item,
	// as determined by dependencies of other items.
	// Item can be also from a subgraph (direct or nested).
	IncomingEdges(ItemRef) EdgeIterator
	// DetectCycle checks if the graph contains a cycle (which it should not,
	// dependency graph is supposed to be DAG) and the first one found is returned
	// as a list of references to items inside the cycle (with the order of the cycle).
	// Complexity is O(V+E).
	DetectCycle() []ItemRef

	// PrivateData returns whatever custom data has the user stored with the graph.
	PrivateData() interface{}
}

// Item is something that can be created, modified and deleted, essentially a stateful
// object. This could be for example a network interface, volume instance, configuration
// file, etc. In this dependency graph, each item instance makes one graph node.
// Beware that items are stored inside the graph and their content should not change
// in any other way than through the Graph APIs. It is recommended to implement the Item
// interface with *value* receivers (or alternatively pass *copied* item values to the graph).
type Item interface {
	// Name should return a unique string identifier for the item instance.
	// It is required for the name to be unique only within item instances of the
	// same type (see Type()). A globally unique item identifier is therefore
	// a combination of the item type and the item name.
	Name() string
	// Label is an optional alternative name that does not have to be unique.
	// It is only used in the graph visualization as the label for the graph node
	// that represents the item. If empty string is returned, Item.Name() is used
	// for labeling instead.
	Label() string
	// Type should return the name of the item type.
	// This is something like reflect.TypeOf(item).Name(), but potentially much more
	// human-readable.
	// For example, type could be "Linux bridge".
	Type() string
	// Equal compares this and the other item instance (of the same type and name)
	// for equivalency. For the purposes of state reconciliation (see libs/reconciler),
	// Equal determines if the current and the new intended state of an item is equal,
	// or if a state transition is needed.
	// Note that if two items are equal, their dependencies should be the same!
	Equal(Item) bool
	// External should return true for items which are not managed (created/modified/deleted)
	// by the caller/owner. This could be used for items created by other management agents
	// or to represent system notifications (e.g. interface link is up).
	// For reconciliation, the presence of external items in the graph is used only for
	// dependency purposes (e.g. create A only after another microservice created B).
	External() bool
	// String should return a human-readable description of the item instance.
	// (e.g. a network interface configuration)
	String() string
	// Dependencies returns a list of all dependencies that have to be satisfied before
	// the item can be created (i.e. dependencies in the returned list are AND-ed).
	// Should be empty for external item (see Item.External()).
	Dependencies() []Dependency
}

// ItemState should store state information for an item instance.
// This can be used for state reconciliation purposes for example.
// It is used by the Reconciler (see libs/reconciler).
// Beware that items are stored inside the graph and their content should not change
// in any other way than through the Graph APIs. It is recommended to implement the ItemState
// interface with *value* receivers (or alternatively pass *copied* values to the graph).
type ItemState interface {
	// String should return a human-readable description of the item state.
	String() string
	// IsCreated should return true if the item is actually created.
	// Return false to model a scenario such as item not being created due to
	// a missing dependency, or failing to get created, etc.
	IsCreated() bool
	// WithError should return non-nil error if the last state transition
	// for this item failed. The error should describe why the item is in a failed
	// state.
	WithError() error
	// InTransition should return true if an item state transition is in progress.
	InTransition() bool
}

// ItemRef is used to uniquely reference item inside the graph.
type ItemRef struct {
	ItemType string
	ItemName string
}

// Reference is a simple helper to make a reference to an item.
func Reference(item Item) ItemRef {
	return ItemRef{
		ItemType: item.Type(),
		ItemName: item.Name(),
	}
}

// String returns string representation of an item reference.
func (ref ItemRef) String() string {
	return ref.ItemType + "/" + ref.ItemName
}

// ItemWithState just wraps item with its state data together under one struct.
// Only used with InitArgs.
type ItemWithState struct {
	Item  Item
	State ItemState
}

// Compare returns an integer comparing two Item references.
// The result will be 0 if ref==ref2, -1 if ref < ref2, and +1 if ref > ref2.
// This allows you to have an ordering for a list of items.
func (ref ItemRef) Compare(ref2 ItemRef) int {
	if ref.ItemType < ref2.ItemType {
		return -1
	}
	if ref.ItemType > ref2.ItemType {
		return 1
	}
	if ref.ItemName < ref2.ItemName {
		return -1
	}
	if ref.ItemName > ref2.ItemName {
		return 1
	}
	return 0
}

// SubGraphPath is a relative path from a graph to one of its subgraphs
// (direct or a nested one).
type SubGraphPath struct {
	// Names of subgraphs in the path.
	elems []string
}

// Len returns the path length (the number of nested subgraphs along the way).
func (p SubGraphPath) Len() int {
	return len(p.elems)
}

// Append creates a *new* path with added elements at the end.
func (p SubGraphPath) Append(elems... string) SubGraphPath {
	newElems := make([]string, 0, len(p.elems) + len(elems))
	newElems = append(newElems, p.elems...)
	newElems = append(newElems, elems...)
	return SubGraphPath{
		elems: newElems,
	}
}

// Concatenate creates a *new* path by concatenating this path with another path.
func (p SubGraphPath) Concatenate(p2 SubGraphPath) SubGraphPath {
	return p.Append(p2.elems...)
}

// IsPrefixOf returns true if this path is prefix of the other path.
func (p SubGraphPath) IsPrefixOf(p2 SubGraphPath) bool {
	if len(p.elems) > len(p2.elems) {
		return false
	}
	for i := range p.elems {
		if p.elems[i] != p2.elems[i] {
			return false
		}
	}
	return true
}

// TrimPrefix returns a *new* SubGraphPath which has the given prefix removed
// from this path.
func (p SubGraphPath) TrimPrefix(prefix SubGraphPath) SubGraphPath {
	if !prefix.IsPrefixOf(p) {
		return p
	}
	return SubGraphPath{
		elems: p.elems[len(prefix.elems):],
	}
}

// Compare returns an integer comparing two paths lexicographically.
// The result will be 0 if p==p2, -1 if p < p2, and +1 if p > p2.
// This allows you to have an ordering for a list of subgraph paths.
func (p SubGraphPath) Compare(p2 SubGraphPath) int {
	for i := 0; i < len(p.elems) && i < len(p2.elems); i++ {
		if p.elems[i] < p2.elems[i] {
			return -1
		}
		if p.elems[i] > p2.elems[i] {
			return 1
		}
	}
	if len(p.elems) < len(p2.elems) {
		return -1
	}
	if len(p.elems) > len(p2.elems) {
		return 1
	}
	return 0
}

// NewSubGraphPath is a constructor for SubGraphPath.
// The path is built by listing the names of subgraphs, each being a child
// of the previous one, leading to a destination subgraph (the last entry).
func NewSubGraphPath(subGraphNames... string) SubGraphPath {
	return SubGraphPath{elems: subGraphNames}
}

// Edge represents a directed edge of a dependency graph.
type Edge struct {
	FromItem ItemRef
	ToItem   ItemRef
	// Dependency represented by this edge.
	Dependency Dependency
}

// Dependency which is considered satisfied if RequiredItem is already created
// and MustSatisfy returns true for that item or is nil.
type Dependency struct {
	// RequiredItem references item which must be already created.
	RequiredItem ItemRef
	// MustSatisfy : used if the required item must not only exist but also satisfy
	// a certain condition. For example, a network route may depend on a specific network
	// interface to exist and also to have a specific IP address assigned. MustSatisfy can
	// check for the presence of the IP address.
	// This function may get called quite often (by Reconciler) so keep it lightweight.
	MustSatisfy func(Item) bool
	// Description : optional description of the dependency.
	Description string
	// Attributes : some additional attributes that may be helpful in special cases
	// to further describe a dependency.
	Attributes DependencyAttributes
}

// DependencyAttributes : some additional attributes that may be helpful in special cases
// to further describe a dependency.
type DependencyAttributes struct {
	// RecreateWhenModified : items that have this dependency should be recreated whenever
	// the required item changes (through Modify).
	RecreateWhenModified bool
	// AutoDeletedByExternal : items that have this dependency are automatically/externally
	// deleted (by other agents or by the managed system itself) whenever the required
	// *external* item is deleted. If the required item is not external (Item.External()
	// returns false), this dependency attribute should be ignored.
	AutoDeletedByExternal bool
}

// ItemIterator iterates items of a graph.
// Items are ordered lexicographically first by subgraphs (in DFS order)
// and secondly by item references.
type ItemIterator interface {
	Iterator

	// Item returns the current Item from the iterator.
	Item() (Item, ItemState)
}

// EdgeIterator iterates outgoing or incoming edges of an item.
// The order of edges is undefined.
type EdgeIterator interface {
	Iterator

	// Edge returns the current Edge from the iterator.
	Edge() Edge
}

// GraphIterator iterates subgraphs of a graph.
// The order of subgraphs is undefined.
type GraphIterator interface {
	Iterator

	// SubGraph returns the current subgraph from the iterator.
	SubGraph() GraphR
}

// Iterator : a common iterator interface.
// Note that it is undefined what happens if the iterated set is changed
// during iteration! Do not add/remove item during iteration.
type Iterator interface {
	// Next advances the iterator and returns whether the next call
	// to the Item()/Edge()/... method will return a non-nil value.
	// Next should be called prior to any call to the iterator's
	// item retrieval method after the iterator has been obtained or reset.
	Next() bool

	// Len returns the number of items remaining in the iterator.
	Len() int

	// Reset returns the iterator to its start position.
	Reset()
}

// InitArgs : input arguments to use with the (sub)graph constructor New().
type InitArgs struct {
	// Name of the graph.
	Name string
	// Description for the graph.
	Description string
	// ItemsWithState : items inside the graph with state data attached.
	ItemsWithState []ItemWithState
	// Items : items inside the graph without state data attached.
	// Use this instead of ItemsWithState to avoid passing ItemState as nil.
	// This makes the code shorter and easier to read.
	// But do not put the same Item into both Items and ItemsWithState.
	Items []Item
	// List of subgraphs directly under this graph.
	Subgraphs []InitArgs
	// PrivateData for the user of the graph to store anything.
	PrivateData interface{}
}

// GetGraphRoot is a simple helper which returns the top-most parent graph
// for a given (sub)graph.
func GetGraphRoot(graph Graph) Graph {
	if graph == nil {
		return nil
	}
	for graph.EditParentGraph() != nil {
		graph = graph.EditParentGraph()
	}
	return graph
}

// GetGraphRootR is a read-only variant for GetGraphRoot.
func GetGraphRootR(graph GraphR) GraphR {
	if graph == nil {
		return nil
	}
	for graph.ParentGraph() != nil {
		graph = graph.ParentGraph()
	}
	return graph
}

// GetSubGraph is a simple helper which allows to obtain subgraph
// by a relative path (which is for example returned by GraphR.Item()).
func GetSubGraph(graph Graph, path SubGraphPath) Graph {
	if graph == nil {
		return nil
	}
	for _, name := range path.elems {
		graphR := graph.SubGraph(name)
		if graphR == nil {
			return nil
		}
		graph = graph.EditSubGraph(graphR)
	}
	return graph
}

// GetSubGraphR is a read-only variant for GetSubGraph.
func GetSubGraphR(graph GraphR, path SubGraphPath) GraphR {
	if graph == nil {
		return nil
	}
	for _, name := range path.elems {
		graph = graph.SubGraph(name)
		if graph == nil {
			return nil
		}
	}
	return graph
}

// PutItemInto is a helper which allows to add or move (and update) item
// into the selected subgraph.
// Returns true if the path refers to an existing subgraph and the item
// was successfully put, false otherwise.
func PutItemInto(graph Graph, item Item, state ItemState, path SubGraphPath) bool {
	subGraph := GetSubGraph(graph, path)
	if subGraph == nil {
		return false
	}
	subGraph.PutItem(item, state)
	return true
}

// DelItemFrom is a helper which allows to remove item from the selected subgraph.
// Returns true if the path refers to an existing subgraph and the item existed
// and was successfully removed, false otherwise.
func DelItemFrom(graph Graph, item ItemRef, path SubGraphPath) bool {
	subGraph := GetSubGraph(graph, path)
	if subGraph == nil {
		return false
	}
	return subGraph.DelItem(item)
}