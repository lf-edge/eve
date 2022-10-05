// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package depgraph_test

import (
	"errors"
	"strings"
	"testing"

	. "github.com/lf-edge/eve/libs/depgraph"
	. "github.com/onsi/gomega"
)

// Rotate cycle to begin with itemRef with lowest name by string ordering.
func rotateCycle(cycle []ItemRef) (rotated []ItemRef) {
	if len(cycle) == 0 {
		return cycle
	}
	var minIdx int
	for i := 1; i < len(cycle); i++ {
		if cycle[i].ItemName < cycle[minIdx].ItemName {
			minIdx = i
		}
	}
	rotated = append(rotated, cycle[minIdx:]...)
	rotated = append(rotated, cycle[:minIdx]...)
	return rotated
}

func TestItemsWithoutDependencies(test *testing.T) {
	t := NewGomegaWithT(test)

	itemA := mockItem{
		name:     "A",
		itemType: "type1",
		attrs:    mockItemAttrs{intAttr: 10, strAttr: "abc"},
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type1",
		attrs:    mockItemAttrs{boolAttr: true},
	}
	itemC := mockItem{
		name:     "C",
		itemType: "type2",
	}

	initArgs := InitArgs{
		Name:        "Graph without edges",
		Description: "This graph has items without dependencies",
		Items:       []Item{itemA, itemB, itemC},
	}
	g := New(initArgs)
	t.Expect(g).ToNot(BeNil())
	t.Expect(g.Name()).To(Equal(initArgs.Name))
	t.Expect(g.Description()).To(Equal(initArgs.Description))
	t.Expect(g.SubGraphs().Len()).To(BeZero())
	t.Expect(g.SubGraphs().Next()).To(BeFalse())
	t.Expect(g.ParentGraph()).To(BeNil())
	t.Expect(g.DetectCycle()).To(BeEmpty())

	g.SetDescription("Updated description")
	t.Expect(g.Description()).To(Equal("Updated description"))

	item, state, path, found := g.Item(Reference(itemA))
	t.Expect(found).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(state).To(BeNil())
	t.Expect(item).To(Equal(itemA))

	t.Expect(g.Items(true)).To(ContainItem(itemA))
	t.Expect(g.Items(true)).To(ContainItem(itemB))
	t.Expect(g.Items(true)).To(ContainItem(itemC))
	t.Expect(g.Items(true).Len()).To(Equal(3))

	edges := g.OutgoingEdges(Reference(itemA))
	t.Expect(edges.Len()).To(BeZero())
	t.Expect(edges.Next()).To(BeFalse())
	edges = g.IncomingEdges(Reference(itemA))
	t.Expect(edges.Len()).To(BeZero())
	t.Expect(edges.Next()).To(BeFalse())

	subgraphs := g.SubGraphs()
	t.Expect(subgraphs.Len()).To(BeZero())
	t.Expect(subgraphs.Next()).To(BeFalse())

	deleted := g.DelItem(Reference(itemB))
	t.Expect(deleted).To(BeTrue())

	_, _, _, found = g.Item(Reference(itemB))
	t.Expect(found).To(BeFalse())

	t.Expect(g.Items(true)).To(ContainItem(itemA))
	t.Expect(g.Items(true)).ToNot(ContainItem(itemB))
	t.Expect(g.Items(true)).To(ContainItem(itemC))
	t.Expect(g.Items(true).Len()).To(Equal(2))

	deleted = g.DelItem(Reference(itemB))
	t.Expect(deleted).To(BeFalse())
	t.Expect(g.Items(true).Len()).To(Equal(2))

	state = &mockItemState{}
	g.PutItem(itemB, state)
	t.Expect(g.Items(true)).To(ContainItem(itemA))
	t.Expect(g.Items(true)).To(ContainItemWithState(itemB, state))
	t.Expect(g.Items(true)).To(ContainItem(itemC))
	t.Expect(g.Items(true).Len()).To(Equal(3))
}

func TestDependencies(test *testing.T) {
	t := NewGomegaWithT(test)

	itemA := mockItem{
		name:     "A",
		itemType: "type1",
		attrs:    mockItemAttrs{intAttr: 10, strAttr: "abc"},
		deps: []Dependency{
			{RequiredItem: ItemRef{
				ItemType: "type2",
				ItemName: "C",
			}},
		},
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type1",
		attrs:    mockItemAttrs{boolAttr: true},
		deps: []Dependency{
			{RequiredItem: ItemRef{
				ItemType: "type2",
				ItemName: "C",
			}},
		},
	}
	itemC := mockItem{
		name:     "C",
		itemType: "type2",
	}

	initArgs := InitArgs{
		Name:        "Graph with edges",
		Description: "This graph has items with dependencies",
		Items:       []Item{itemA, itemB, itemC},
	}
	g := New(initArgs)
	t.Expect(g).ToNot(BeNil())

	edges := g.OutgoingEdges(Reference(itemA))
	t.Expect(edges).To(ContainEdge(Reference(itemA), Reference(itemC)))
	t.Expect(edges.Len()).To(Equal(1))
	edges = g.IncomingEdges(Reference(itemA))
	t.Expect(edges.Len()).To(BeZero())

	edges = g.OutgoingEdges(Reference(itemB))
	t.Expect(edges).To(ContainEdge(Reference(itemB), Reference(itemC)))
	t.Expect(edges.Len()).To(Equal(1))
	edges = g.IncomingEdges(Reference(itemB))
	t.Expect(edges.Len()).To(BeZero())

	edges = g.OutgoingEdges(Reference(itemC))
	t.Expect(edges.Len()).To(BeZero())
	edges = g.IncomingEdges(Reference(itemC))
	t.Expect(edges).To(ContainEdge(Reference(itemA), Reference(itemC)))
	t.Expect(edges).To(ContainEdge(Reference(itemB), Reference(itemC)))
	t.Expect(edges.Len()).To(Equal(2))

	t.Expect(g.DetectCycle()).To(BeEmpty())

	// Add new dependency.
	itemA.deps = append(itemA.deps, Dependency{
		RequiredItem: ItemRef{
			ItemType: "type1",
			ItemName: "B",
		},
	})
	g.PutItem(itemA, nil)

	edges = g.OutgoingEdges(Reference(itemA))
	t.Expect(edges).To(ContainEdge(Reference(itemA), Reference(itemC)))
	t.Expect(edges).To(ContainEdge(Reference(itemA), Reference(itemB)))
	t.Expect(edges.Len()).To(Equal(2))
	edges = g.IncomingEdges(Reference(itemA))
	t.Expect(edges.Len()).To(BeZero())

	edges = g.OutgoingEdges(Reference(itemB))
	t.Expect(edges).To(ContainEdge(Reference(itemB), Reference(itemC)))
	t.Expect(edges.Len()).To(Equal(1))
	edges = g.IncomingEdges(Reference(itemB))
	t.Expect(edges).To(ContainEdge(Reference(itemA), Reference(itemB)))
	t.Expect(edges.Len()).To(Equal(1))

	edges = g.OutgoingEdges(Reference(itemC))
	t.Expect(edges.Len()).To(BeZero())
	edges = g.IncomingEdges(Reference(itemC))
	t.Expect(edges).To(ContainEdge(Reference(itemA), Reference(itemC)))
	t.Expect(edges).To(ContainEdge(Reference(itemB), Reference(itemC)))
	t.Expect(edges.Len()).To(Equal(2))

	t.Expect(g.DetectCycle()).To(BeEmpty())

	g.DelItem(Reference(itemA))

	edges = g.IncomingEdges(Reference(itemA))
	t.Expect(edges.Len()).To(BeZero())
	edges = g.OutgoingEdges(Reference(itemA))
	t.Expect(edges.Len()).To(BeZero())

	edges = g.OutgoingEdges(Reference(itemB))
	t.Expect(edges).To(ContainEdge(Reference(itemB), Reference(itemC)))
	t.Expect(edges.Len()).To(Equal(1))
	edges = g.IncomingEdges(Reference(itemB))
	t.Expect(edges.Len()).To(BeZero())

	edges = g.OutgoingEdges(Reference(itemC))
	t.Expect(edges.Len()).To(BeZero())
	edges = g.IncomingEdges(Reference(itemC))
	t.Expect(edges).To(ContainEdge(Reference(itemB), Reference(itemC)))
	t.Expect(edges.Len()).To(Equal(1))

	// Create a cycle.
	itemC.deps = append(itemC.deps, Dependency{
		RequiredItem: ItemRef{
			ItemType: "type1",
			ItemName: "B",
		},
	})
	g.PutItem(itemC, nil)

	edges = g.OutgoingEdges(Reference(itemB))
	t.Expect(edges).To(ContainEdge(Reference(itemB), Reference(itemC)))
	t.Expect(edges.Len()).To(Equal(1))
	edges = g.IncomingEdges(Reference(itemB))
	t.Expect(edges).To(ContainEdge(Reference(itemC), Reference(itemB)))
	t.Expect(edges.Len()).To(Equal(1))

	edges = g.OutgoingEdges(Reference(itemC))
	t.Expect(edges).To(ContainEdge(Reference(itemC), Reference(itemB)))
	t.Expect(edges.Len()).To(Equal(1))
	edges = g.IncomingEdges(Reference(itemC))
	t.Expect(edges).To(ContainEdge(Reference(itemB), Reference(itemC)))
	t.Expect(edges.Len()).To(Equal(1))

	cycle := g.DetectCycle()
	t.Expect(cycle).To(HaveLen(2))
	cycle = rotateCycle(cycle)
	t.Expect(cycle[0]).To(Equal(Reference(itemB)))
	t.Expect(cycle[1]).To(Equal(Reference(itemC)))
}

func TestSubGraphs(test *testing.T) {
	t := NewGomegaWithT(test)

	// Items & Subgraphs: [A B [C D [E]] [F] []]
	// Dependencies: A->B, C->B, D->C, F->B
	itemA := mockItem{
		name:     "A",
		itemType: "type1",
		attrs:    mockItemAttrs{intAttr: 10, strAttr: "abc"},
		deps: []Dependency{
			{RequiredItem: ItemRef{
				ItemType: "type1",
				ItemName: "B",
			}},
		},
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type1",
		attrs:    mockItemAttrs{boolAttr: true},
	}
	itemC := mockItem{
		name:     "C",
		itemType: "type1",
		deps: []Dependency{
			{RequiredItem: ItemRef{
				ItemType: "type1",
				ItemName: "B",
			}},
		},
	}
	itemD := mockItem{
		name:     "D",
		itemType: "type2",
		deps: []Dependency{
			{RequiredItem: ItemRef{
				ItemType: "type1",
				ItemName: "C",
			}},
		},
	}
	itemE := mockItem{
		name:     "E",
		itemType: "type3",
	}
	itemF := mockItem{
		name:     "F",
		itemType: "type2",
		deps: []Dependency{
			{RequiredItem: ItemRef{
				ItemType: "type1",
				ItemName: "B",
			}},
		},
	}

	initArgs := InitArgs{
		Name:        "RootGraph",
		Description: "This graph contains subgraphs",
		Items:       []Item{itemA, itemB},
		Subgraphs: []InitArgs{
			{
				Name:  "SubGraph1",
				Items: []Item{itemC, itemD},
				Subgraphs: []InitArgs{
					{
						Name:  "NestedSubGraph",
						Items: []Item{itemE},
					},
				},
			},
			{
				Name:  "SubGraph2",
				Items: []Item{itemF},
			},
			{
				Name: "SubGraph3",
			},
		},
	}
	g := New(initArgs)
	t.Expect(g).ToNot(BeNil())

	directItems := g.Items(false)
	t.Expect(directItems).To(ContainItem(itemA))
	t.Expect(directItems).To(ContainItem(itemB))
	t.Expect(directItems).ToNot(ContainItem(itemC))
	t.Expect(directItems.Len()).To(Equal(2))
	allItems := g.Items(true)
	t.Expect(allItems).To(ContainItem(itemA))
	t.Expect(allItems).To(ContainItem(itemB))
	t.Expect(allItems).To(ContainItem(itemC))
	t.Expect(allItems).To(ContainItem(itemD))
	t.Expect(allItems).To(ContainItem(itemE))
	t.Expect(allItems).To(ContainItem(itemF))
	t.Expect(allItems.Len()).To(Equal(6))

	edges := g.OutgoingEdges(Reference(itemA))
	t.Expect(edges).To(ContainEdge(Reference(itemA), Reference(itemB)))
	t.Expect(edges.Len()).To(Equal(1))
	edges = g.IncomingEdges(Reference(itemA))
	t.Expect(edges.Len()).To(BeZero())

	edges = g.OutgoingEdges(Reference(itemB))
	t.Expect(edges.Len()).To(BeZero())
	edges = g.IncomingEdges(Reference(itemB))
	t.Expect(edges).To(ContainEdge(Reference(itemA), Reference(itemB)))
	t.Expect(edges).To(ContainEdge(Reference(itemC), Reference(itemB)))
	t.Expect(edges).To(ContainEdge(Reference(itemF), Reference(itemB)))
	t.Expect(edges.Len()).To(Equal(3))

	edges = g.OutgoingEdges(Reference(itemC))
	t.Expect(edges).To(ContainEdge(Reference(itemC), Reference(itemB)))
	t.Expect(edges.Len()).To(Equal(1))
	edges = g.IncomingEdges(Reference(itemC))
	t.Expect(edges).To(ContainEdge(Reference(itemD), Reference(itemC)))
	t.Expect(edges.Len()).To(Equal(1))

	edges = g.OutgoingEdges(Reference(itemD))
	t.Expect(edges).To(ContainEdge(Reference(itemD), Reference(itemC)))
	t.Expect(edges.Len()).To(Equal(1))
	edges = g.IncomingEdges(Reference(itemD))
	t.Expect(edges.Len()).To(BeZero())

	edges = g.OutgoingEdges(Reference(itemE))
	t.Expect(edges.Len()).To(BeZero())
	edges = g.IncomingEdges(Reference(itemE))
	t.Expect(edges.Len()).To(BeZero())

	edges = g.OutgoingEdges(Reference(itemF))
	t.Expect(edges).To(ContainEdge(Reference(itemF), Reference(itemB)))
	t.Expect(edges.Len()).To(Equal(1))
	edges = g.IncomingEdges(Reference(itemF))
	t.Expect(edges.Len()).To(BeZero())

	t.Expect(g.DetectCycle()).To(BeEmpty())

	subgraph1 := g.SubGraph("SubGraph1")
	t.Expect(subgraph1).ToNot(BeNil())
	subgraph2 := g.SubGraph("SubGraph2")
	t.Expect(subgraph2).ToNot(BeNil())
	subgraph3 := g.SubGraph("SubGraph3")
	t.Expect(subgraph3).ToNot(BeNil())
	t.Expect(g.SubGraph("SubGraph4")).To(BeNil())

	directItems = subgraph1.Items(false)
	t.Expect(directItems).To(ContainItem(itemC))
	t.Expect(directItems).To(ContainItem(itemD))
	t.Expect(directItems).ToNot(ContainItem(itemA))
	t.Expect(directItems).ToNot(ContainItem(itemE))
	t.Expect(directItems).ToNot(ContainItem(itemF))
	t.Expect(directItems.Len()).To(Equal(2))

	allItems = subgraph1.Items(true)
	t.Expect(allItems).To(ContainItem(itemC))
	t.Expect(allItems).To(ContainItem(itemD))
	t.Expect(allItems).ToNot(ContainItem(itemA))
	t.Expect(allItems).To(ContainItem(itemE))
	t.Expect(allItems).ToNot(ContainItem(itemF))
	t.Expect(allItems.Len()).To(Equal(3))

	edges = subgraph1.OutgoingEdges(Reference(itemC))
	t.Expect(edges).To(ContainEdge(Reference(itemC), Reference(itemB)))
	t.Expect(edges.Len()).To(Equal(1))
	edges = subgraph1.IncomingEdges(Reference(itemC))
	t.Expect(edges).To(ContainEdge(Reference(itemD), Reference(itemC)))
	t.Expect(edges.Len()).To(Equal(1))

	edges = subgraph1.OutgoingEdges(Reference(itemA))
	t.Expect(edges.Len()).To(BeZero())
	edges = subgraph1.IncomingEdges(Reference(itemA))
	t.Expect(edges.Len()).To(BeZero())

	directItems = subgraph2.Items(false)
	t.Expect(directItems).To(ContainItem(itemF))
	t.Expect(directItems.Len()).To(Equal(1))

	allItems = subgraph2.Items(true)
	t.Expect(allItems).To(ContainItem(itemF))
	t.Expect(allItems.Len()).To(Equal(1))

	directItems = subgraph3.Items(false)
	t.Expect(directItems.Len()).To(BeZero())

	allItems = subgraph3.Items(true)
	t.Expect(allItems.Len()).To(BeZero())

	t.Expect(g.SubGraphs()).To(ContainSubGraph("SubGraph1"))
	t.Expect(g.SubGraphs()).To(ContainSubGraph("SubGraph2"))
	t.Expect(g.SubGraphs()).To(ContainSubGraph("SubGraph3"))
	t.Expect(g.SubGraphs().Len()).To(Equal(3))

	t.Expect(subgraph1.SubGraphs()).To(ContainSubGraph("NestedSubGraph"))
	t.Expect(subgraph1.SubGraphs().Len()).To(Equal(1))
	t.Expect(subgraph2.SubGraphs().Len()).To(BeZero())
	t.Expect(subgraph3.SubGraphs().Len()).To(BeZero())
	t.Expect(subgraph1.ParentGraph()).To(Equal(g))

	iter := subgraph1.SubGraphs()
	t.Expect(iter.Next()).To(BeTrue())
	nestedSubGraph := iter.SubGraph()
	t.Expect(nestedSubGraph).To(Equal(subgraph1.SubGraph("NestedSubGraph")))
	t.Expect(nestedSubGraph.ParentGraph()).To(Equal(subgraph1))

	directItems = nestedSubGraph.Items(false)
	t.Expect(directItems).To(ContainItem(itemE))
	t.Expect(directItems.Len()).To(Equal(1))

	allItems = nestedSubGraph.Items(true)
	t.Expect(allItems).To(ContainItem(itemE))
	t.Expect(allItems.Len()).To(Equal(1))

	// Update Subgraph, move itemA + itemF where itemE was
	subGraphArgs := InitArgs{
		Name:  "NestedSubGraph",
		Items: []Item{itemA, itemF},
	}
	newNestedSubGraph := New(subGraphArgs)
	t.Expect(newNestedSubGraph).ToNot(BeNil())
	subG1RW := g.EditSubGraph(subgraph1)
	t.Expect(subG1RW).ToNot(BeNil())
	t.Expect(subG1RW.EditParentGraph()).To(Equal(g))
	subG1RW.PutSubGraph(newNestedSubGraph)

	t.Expect(g.Items(true)).ToNot(ContainItem(itemE))
	t.Expect(subgraph1.SubGraphs()).To(ContainSubGraph("NestedSubGraph"))
	t.Expect(subgraph1.SubGraphs().Len()).To(Equal(1))
	allItems = subgraph1.Items(true)
	t.Expect(allItems).To(ContainItem(itemA))
	t.Expect(allItems).To(ContainItem(itemF))
	t.Expect(allItems).ToNot(ContainItem(itemE))
	t.Expect(allItems.Len()).To(Equal(4))

	directItems = g.Items(false)
	t.Expect(directItems).ToNot(ContainItem(itemA))
	t.Expect(directItems).To(ContainItem(itemB))
	t.Expect(directItems.Len()).To(Equal(1))

	nestedSubGraph = GetSubGraphR(g, SubGraphPath{}.Append("SubGraph1", "NestedSubGraph"))
	t.Expect(nestedSubGraph).ToNot(BeNil())

	directItems = nestedSubGraph.Items(false)
	t.Expect(directItems).To(ContainItem(itemA))
	t.Expect(directItems).To(ContainItem(itemF))
	t.Expect(directItems.Len()).To(Equal(2))

	allItems = nestedSubGraph.Items(true)
	t.Expect(allItems).To(ContainItem(itemA))
	t.Expect(allItems).To(ContainItem(itemF))
	t.Expect(allItems.Len()).To(Equal(2))

	subgraph2 = g.SubGraph("SubGraph2")
	t.Expect(subgraph2).ToNot(BeNil())
	directItems = subgraph2.Items(false)
	t.Expect(directItems.Len()).To(BeZero())
	allItems = subgraph2.Items(true)
	t.Expect(allItems.Len()).To(BeZero())

	// Create cycle - just for testing purposes.
	itemB = mockItem{
		name:     "B",
		itemType: "type1",
		attrs:    mockItemAttrs{boolAttr: true},
		deps: []Dependency{
			{RequiredItem: ItemRef{
				ItemType: "type2",
				ItemName: "D",
			}},
		},
	}
	PutItemInto(g, itemB, nil, SubGraphPath{})
	cycle := g.DetectCycle()
	t.Expect(cycle).To(HaveLen(3))
	cycle = rotateCycle(cycle)
	t.Expect(cycle[0]).To(Equal(Reference(itemB)))
	t.Expect(cycle[1]).To(Equal(Reference(itemD)))
	t.Expect(cycle[2]).To(Equal(Reference(itemC)))

	// Remove SubGraph1 and the nested one
	t.Expect(g.DelSubGraph("SubGraph1")).To(BeTrue())
	allItems = g.Items(true)
	t.Expect(allItems).To(ContainItem(itemB))
	t.Expect(allItems.Len()).To(Equal(1))

	t.Expect(g.SubGraphs()).ToNot(ContainSubGraph("SubGraph1"))
	t.Expect(g.SubGraphs()).To(ContainSubGraph("SubGraph2"))
	t.Expect(g.SubGraphs()).To(ContainSubGraph("SubGraph3"))
	t.Expect(g.SubGraphs().Len()).To(Equal(2))

	edges = g.OutgoingEdges(Reference(itemA))
	t.Expect(edges.Len()).To(BeZero())
	edges = g.IncomingEdges(Reference(itemA))
	t.Expect(edges.Len()).To(BeZero())

	edges = g.OutgoingEdges(Reference(itemB))
	t.Expect(edges).To(ContainEdge(Reference(itemB), Reference(itemD)))
	t.Expect(edges.Len()).To(Equal(1))
	edges = g.IncomingEdges(Reference(itemB))
	t.Expect(edges.Len()).To(BeZero())
}

func TestItemAsGraph(test *testing.T) {
	t := NewGomegaWithT(test)

	// Graph1:
	// Items & Subgraphs: [A [B C]]
	// Dependencies: A->B, B->C
	itemA := mockItem{
		name:     "A",
		itemType: "type1",
		attrs:    mockItemAttrs{intAttr: 10, strAttr: "abc"},
		deps: []Dependency{
			{RequiredItem: ItemRef{
				ItemType: "type1",
				ItemName: "B",
			}},
		},
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type1",
		attrs:    mockItemAttrs{boolAttr: true},
		deps: []Dependency{
			{RequiredItem: ItemRef{
				ItemType: "type2",
				ItemName: "C",
			}},
		},
	}
	itemC := mockItem{
		name:     "C",
		itemType: "type2",
	}
	initArgs := InitArgs{
		Name:  "Graph1",
		Items: []Item{itemA},
		Subgraphs: []InitArgs{
			{
				Name:  "SubGraph1",
				Items: []Item{itemB, itemC},
			},
		},
	}
	g := New(initArgs)
	t.Expect(g).ToNot(BeNil())

	bAsGraph := g.ItemAsSubGraph(Reference(itemB))
	t.Expect(bAsGraph.Name()).To(Equal(Reference(itemB).String()))
	t.Expect(bAsGraph.Description()).To(BeEmpty())
	t.Expect(bAsGraph.DetectCycle()).To(BeEmpty())
	t.Expect(bAsGraph.ParentGraph()).To(Equal(g.SubGraph("SubGraph1")))
	t.Expect(bAsGraph.SubGraphs().Len()).To(BeZero())
	t.Expect(bAsGraph.PrivateData()).To(BeNil())
	t.Expect(bAsGraph.Items(true)).To(ContainItem(itemB))
	t.Expect(bAsGraph.Items(true).Len()).To(Equal(1))
	t.Expect(bAsGraph.Items(false)).To(ContainItem(itemB))
	t.Expect(bAsGraph.Items(false).Len()).To(Equal(1))

	item, state, path, found := bAsGraph.Item(Reference(itemB))
	t.Expect(found).To(BeTrue())
	t.Expect(item).To(Equal(itemB))
	t.Expect(state).To(BeNil())
	t.Expect(path).To(Equal(SubGraphPath{}))

	item, state, path, found = g.Item(Reference(itemB))
	t.Expect(found).To(BeTrue())
	t.Expect(item).To(Equal(itemB))
	t.Expect(state).To(BeNil())
	t.Expect(path).To(Equal(SubGraphPath{}.Append("SubGraph1")))

	_, _, _, found = bAsGraph.Item(Reference(itemA))
	t.Expect(found).To(BeFalse())
	_, _, _, found = bAsGraph.Item(Reference(itemC))
	t.Expect(found).To(BeFalse())

	edges := bAsGraph.OutgoingEdges(Reference(itemB))
	t.Expect(edges).To(ContainEdge(Reference(itemB), Reference(itemC)))
	t.Expect(edges.Len()).To(Equal(1))
	edges = bAsGraph.IncomingEdges(Reference(itemB))
	t.Expect(edges).To(ContainEdge(Reference(itemA), Reference(itemB)))
	t.Expect(edges.Len()).To(Equal(1))

	edges = bAsGraph.OutgoingEdges(Reference(itemA))
	t.Expect(edges.Len()).To(BeZero())
	edges = bAsGraph.IncomingEdges(Reference(itemA))
	t.Expect(edges.Len()).To(BeZero())

	edges = bAsGraph.OutgoingEdges(Reference(itemC))
	t.Expect(edges.Len()).To(BeZero())
	edges = bAsGraph.IncomingEdges(Reference(itemC))
	t.Expect(edges.Len()).To(BeZero())

	g1 := g.ItemAsSubGraph(Reference(itemB))
	g2 := g.ItemAsSubGraph(Reference(itemB))
	t.Expect(g1.DiffItems(g2)).To(BeEmpty())
	diff := g1.DiffItems(nil)
	t.Expect(diff).To(ContainItem(itemB))
	t.Expect(diff).To(HaveLen(1))

	bAsGraphRW := g.EditSubGraph(bAsGraph)
	t.Expect(bAsGraphRW).ToNot(BeNil())
	t.Expect(bAsGraphRW.EditParentGraph()).To(Equal(g.SubGraph("SubGraph1")))
	itemB.attrs.boolAttr = false
	bAsGraphRW.PutItem(itemB, nil)
	t.Expect(g.Items(true)).To(ContainItem(itemB))
	t.Expect(bAsGraphRW.DelItem(Reference(itemB))).To(BeTrue())
	t.Expect(bAsGraph.Items(true)).ToNot(ContainItem(itemB))
	t.Expect(bAsGraph.Items(true).Len()).To(BeZero())
	t.Expect(g.Items(true)).ToNot(ContainItem(itemB))
}

func TestDiffItems(test *testing.T) {
	t := NewGomegaWithT(test)

	// Graph1:
	// Items & Subgraphs: [A B [C] [D]]
	itemA := mockItem{
		name:     "A",
		itemType: "type1",
		attrs:    mockItemAttrs{intAttr: 10, strAttr: "abc"},
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type1",
		attrs:    mockItemAttrs{boolAttr: true},
	}
	itemC := mockItem{
		name:     "C",
		itemType: "type1",
	}
	itemD := mockItem{
		name:     "D",
		itemType: "type2",
	}
	initArgs := InitArgs{
		Name:  "Graph1",
		Items: []Item{itemA, itemB},
		Subgraphs: []InitArgs{
			{
				Name:  "SubGraph1",
				Items: []Item{itemC},
			},
			{
				Name:  "SubGraph2",
				Items: []Item{itemD},
			},
		},
	}
	g1 := New(initArgs)
	t.Expect(g1).ToNot(BeNil())

	// Graph2:
	// Items & Subgraphs: [A B' [E] [C]]
	itemA = mockItem{
		name:     "A",
		itemType: "type1",
		attrs:    mockItemAttrs{intAttr: 10, strAttr: "abc"},
	}
	itemB = mockItem{
		name:     "B",
		itemType: "type1",
		attrs:    mockItemAttrs{boolAttr: false}, // different
	}
	itemC = mockItem{
		name:     "C",
		itemType: "type1",
	}
	itemE := mockItem{
		name:     "E",
		itemType: "type2",
	}
	initArgs = InitArgs{
		Name:  "Graph2",
		Items: []Item{itemA, itemB},
		Subgraphs: []InitArgs{
			{
				Name:  "SubGraph1",
				Items: []Item{itemE},
			},
			{
				Name:  "SubGraph2",
				Items: []Item{itemC},
			},
		},
	}
	g2 := New(initArgs)
	t.Expect(g2).ToNot(BeNil())

	diff := g1.DiffItems(g2)
	t.Expect(diff).ToNot(ContainItem(itemA))
	t.Expect(diff).To(ContainItem(itemB)) // different attributes
	t.Expect(diff).To(ContainItem(itemC)) // different subgraph
	t.Expect(diff).To(ContainItem(itemD)) // not in g2
	t.Expect(diff).To(ContainItem(itemE)) // not in g1
	t.Expect(diff).To(HaveLen(4))

	diff = g1.DiffItems(nil)
	t.Expect(diff).To(ContainItem(itemA))
	t.Expect(diff).To(ContainItem(itemB))
	t.Expect(diff).To(ContainItem(itemC))
	t.Expect(diff).To(ContainItem(itemD))
	t.Expect(diff).To(HaveLen(4))

	// Graph3:
	// - mostly like Graph2 but with a different path to the root,
	//   which should not make any difference
	// Items & Subgraphs: [[A B [E'] [C]]]
	itemA = mockItem{
		name:     "A",
		itemType: "type1",
		attrs:    mockItemAttrs{intAttr: 10, strAttr: "abc"},
	}
	itemB = mockItem{
		name:     "B",
		itemType: "type1",
		attrs:    mockItemAttrs{boolAttr: true}, // like in Graph1
	}
	itemC = mockItem{
		name:     "C",
		itemType: "type1",
	}
	itemE = mockItem{
		name:     "E",
		itemType: "type2",
		attrs:    mockItemAttrs{boolAttr: true}, // different
	}
	initArgs = InitArgs{
		Name:  "RootGraph3",
		Subgraphs: []InitArgs{
			{
				Name: "Graph3",
				Items: []Item{itemA, itemB},
				Subgraphs: []InitArgs{
					{
						Name:  "SubGraph1",
						Items: []Item{itemE},
					},
					{
						Name:  "SubGraph2",
						Items: []Item{itemC},
					},
				},
			},
		},
	}
	g3Root := New(initArgs)
	t.Expect(g3Root).ToNot(BeNil())
	g3 := g3Root.SubGraph("Graph3")
	t.Expect(g3).ToNot(BeNil())

	diff = g3.DiffItems(g1)
	t.Expect(diff).ToNot(ContainItem(itemA))
	t.Expect(diff).ToNot(ContainItem(itemB))
	t.Expect(diff).To(ContainItem(itemC)) // different subgraph
	t.Expect(diff).To(ContainItem(itemD)) // not in g3
	t.Expect(diff).To(ContainItem(itemE)) // not in g1
	t.Expect(diff).To(HaveLen(3))

	diff = g3.DiffItems(g2)
	t.Expect(diff).ToNot(ContainItem(itemA))
	t.Expect(diff).To(ContainItem(itemB)) // different attributes
	t.Expect(diff).ToNot(ContainItem(itemC))
	t.Expect(diff).To(ContainItem(itemE)) // different attributes
	t.Expect(diff).To(HaveLen(2))
}

func TestDotExporter(test *testing.T) {
	t := NewGomegaWithT(test)

	// Graph1:
	// Items & Subgraphs: [A [C]]
	// Dependencies: C->A, C->D
	// A is in a failed state, C is in a transition
	itemA := mockItem{
		name:     "A",
		itemType: "type1",
		attrs:    mockItemAttrs{intAttr: 10, strAttr: "abc"},
	}
	itemC := mockItem{
		name:     "C",
		itemType: "type2",
		deps: []Dependency{
			{
				RequiredItem: ItemRef{
					ItemType: "type1",
					ItemName: "A",
				},
				Description: "C depends on A",
			},
			{
				RequiredItem: ItemRef{
					ItemType: "type2",
					ItemName: "D",
				},
				Description: "C depends on D",
			},
		},
	}
	initArgs := InitArgs{
		Name:  "Graph1",
		ItemsWithState: []ItemWithState{
			{
				Item:  itemA,
				State: mockItemState{
					isCreated: true,
					withErr:   errors.New("failed to modify"),
				},
			},
		},
		Subgraphs: []InitArgs{
			{
				Name: "SubGraph1",
				ItemsWithState: []ItemWithState{
					{
						Item:  itemC,
						State: mockItemState{
							isCreated:    true,
							inTransition: true,
						},
					},
				},
			},
		},
	}
	g1 := New(initArgs)
	t.Expect(g1).ToNot(BeNil())

	// Graph2:
	// Items & Subgraphs: [A B [C] [D]]
	// Dependencies: C->A, C->D, D->B
	itemA = mockItem{
		name:     "A",
		itemType: "type1",
		attrs:    mockItemAttrs{intAttr: 10, strAttr: "abc"},
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type1",
		attrs:    mockItemAttrs{boolAttr: true},
	}
	itemC = mockItem{
		name:     "C",
		itemType: "type2",
		deps: []Dependency{
			{
				RequiredItem: ItemRef{
					ItemType: "type1",
					ItemName: "A",
				},
				Description: "C depends on A",
			},
			{
				RequiredItem: ItemRef{
					ItemType: "type2",
					ItemName: "D",
				},
				Description: "C depends on D",
			},
		},
	}
	itemD := mockItem{
		name:     "D",
		itemType: "type2",
		deps: []Dependency{
			{RequiredItem: ItemRef{
				ItemType: "type1",
				ItemName: "B",
			}},
		},
	}
	initArgs = InitArgs{
		Name:  "Graph1",
		Items: []Item{itemA, itemB},
		Subgraphs: []InitArgs{
			{
				Name:  "SubGraph1",
				Items: []Item{itemC},
			},
			{
				Name:  "SubGraph2",
				Items: []Item{itemD},
			},
		},
	}
	g2 := New(initArgs)
	t.Expect(g2).ToNot(BeNil())

	dotExporter := &DotExporter{
		CheckDeps: true,
	}
	dot, err := dotExporter.Export(g1)
	t.Expect(err).To(BeNil())
	t.Expect(dot).ToNot(BeEmpty())
	t.Expect(dot).To(ContainSubstring("digraph G {"))
	t.Expect(dot).To(ContainSubstring("label = \"Graph1\";"))
	t.Expect(dot).To(ContainSubstring("subgraph cluster_SubGraph1 {"))
	t.Expect(dot).To(MatchRegexp("type1_A \\[color = red,.*shape = ellipse,.*style = filled,.*tooltip = \"item type:type1 name:A with attrs: {10 abc false}\\\\nError: failed to modify\".*label = \"A\"\\];"))
	t.Expect(dot).To(MatchRegexp("type2_C \\[color = blue,.*shape = cds,.*style = filled,.*tooltip = \"item type:type2 name:C with attrs: {0  false}\".*label = \"C\"\\];"))
	t.Expect(dot).To(MatchRegexp("type2_D \\[color = grey,.*shape = ellipse,.*style = dashed,.*tooltip = \"<missing>\".*label = \"type2/D\"\\];"))
	t.Expect(dot).To(ContainSubstring("type2_C -> type1_A [color = black, tooltip = \"C depends on A\"];"))
	t.Expect(dot).To(ContainSubstring("type2_C -> type2_D [color = red, tooltip = \"C depends on D\"];"))
	t.Expect(strings.Count(dot, "{")).To(Equal(strings.Count(dot, "}")))

	dot, err = dotExporter.ExportTransition(g1, g2)
	t.Expect(err).To(BeNil())
	t.Expect(dot).ToNot(BeEmpty())
	t.Expect(dot).To(ContainSubstring("digraph G {"))
	t.Expect(dot).To(ContainSubstring("label = \"Graph1\";"))
	t.Expect(dot).To(ContainSubstring("subgraph cluster_SubGraph1 {"))
	t.Expect(dot).To(ContainSubstring("subgraph cluster_SubGraph2 {"))
	t.Expect(dot).To(MatchRegexp("type1_A \\[color = red,.*shape = ellipse,.*style = filled,.*tooltip = \"item type:type1 name:A with attrs: {10 abc false}\\\\nError: failed to modify\".*label = \"A\"\\];"))
	t.Expect(dot).To(MatchRegexp("type1_B \\[color = grey,.*shape = ellipse,.*style = filled,.*tooltip = \"item type:type1 name:B with attrs: {0  true}\".*label = \"B\"\\];"))
	t.Expect(dot).To(MatchRegexp("type2_C \\[color = blue,.*shape = cds,.*style = filled,.*tooltip = \"item type:type2 name:C with attrs: {0  false}\".*label = \"C\"\\];"))
	t.Expect(dot).To(MatchRegexp("type2_D \\[color = grey,.*shape = ellipse,.*style = filled,.*tooltip = \"item type:type2 name:D with attrs: {0  false}\".*label = \"D\"\\];"))
	t.Expect(dot).To(ContainSubstring("type2_C -> type1_A [color = black, tooltip = \"C depends on A\"];"))
	t.Expect(dot).To(ContainSubstring("type2_C -> type2_D [color = red, tooltip = \"C depends on D\"];"))
	t.Expect(dot).To(ContainSubstring("type2_D -> type1_B [color = red, tooltip = \"\"];"))
	t.Expect(strings.Count(dot, "{")).To(Equal(strings.Count(dot, "}")))
}
