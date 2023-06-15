// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	dg "github.com/lf-edge/eve/libs/depgraph"
	rec "github.com/lf-edge/eve/libs/reconciler"
)

// Reconciliation status is accessed by matchers (see matchers_test.go).
var status rec.Status

func addConfigurator(registry *rec.DefaultRegistry, forItemType string) error {
	return registry.Register(&mockConfigurator{itemType: forItemType}, forItemType)
}

// Items: A, B, C
// Without dependencies
func TestItemsWithoutDependencies(test *testing.T) {
	t := NewGomegaWithT(test)

	itemA := mockItem{
		name:            "A",
		itemType:        "type1",
		modifiableAttrs: mockItemAttrs{intAttr: 10, strAttr: "abc"},
	}
	itemB := mockItem{
		name:            "B",
		itemType:        "type1",
		modifiableAttrs: mockItemAttrs{boolAttr: true},
	}
	itemC := mockItem{
		name:     "C",
		itemType: "type2",
	}

	reg := &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())
	t.Expect(addConfigurator(reg, "type2")).To(Succeed())

	// 0. Empty content of the intended state
	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
	})

	r := rec.New(reg)
	t.Expect(r).ToNot(BeNil())
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.OperationLog).To(BeEmpty())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.CancelAsyncOps).To(BeNil())
	t.Expect(status.ReadyToResume).To(BeNil())
	t.Expect(status.NewCurrentState).ToNot(BeNil())

	current := status.NewCurrentState
	t.Expect(current.Name()).To(Equal(intent.Name()))
	t.Expect(current.Description()).To(Equal(intent.Description()))
	t.Expect(current.Items(true).Len()).To(BeZero())
	t.Expect(current.SubGraphs().Len()).To(BeZero())

	// 1. Create all three items
	intent.PutItem(itemA, nil)
	intent.PutItem(itemB, nil)
	intent.PutItem(itemC, nil)

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeCreated())
	t.Expect(itemB).To(BeCreated())
	t.Expect(itemC).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(3))
	t.Expect(status.OperationLog.String()).ToNot(BeEmpty())

	item, state, path, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData := state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))
	t.Expect(stateData.State.String()).To(Equal("created"))

	// 2. Modify itemB
	itemB.modifiableAttrs.intAttr++
	intent.PutItem(itemB, nil)

	// Let's try to reuse previous reconciler.
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemB).To(BeModified().WithoutPrevError())
	t.Expect(status.OperationLog).To(HaveLen(1))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationModify))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// 3. Put the same itemB, should not trigger Modify
	intent.PutItem(itemB, nil)

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(status.OperationLog).To(BeEmpty())

	// 4. Delete itemA and itemC
	intent.DelItem(dg.Reference(itemA))
	intent.DelItem(dg.Reference(itemC))

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeDeleted().WithoutPrevError())
	t.Expect(itemB).ToNot(BeDeleted())
	t.Expect(itemC).To(BeDeleted().WithoutPrevError())
	t.Expect(status.OperationLog).To(HaveLen(2))

	_, _, _, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())
	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	_, _, _, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeFalse())
}

// Items: A, B, C
// Dependencies: A->C, B->C
func TestDependencyItemIsCreated(test *testing.T) {
	t := NewGomegaWithT(test)

	itemA := mockItem{
		name:            "A",
		itemType:        "type1",
		modifiableAttrs: mockItemAttrs{intAttr: 10, strAttr: "abc"},
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type2",
					ItemName: "C",
				},
			},
		},
	}
	itemB := mockItem{
		name:            "B",
		itemType:        "type1",
		modifiableAttrs: mockItemAttrs{boolAttr: true},
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type2",
					ItemName: "C",
				},
			},
		},
	}
	itemC := mockItem{
		name:     "C",
		itemType: "type2",
	}

	reg := &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())
	t.Expect(addConfigurator(reg, "type2")).To(Succeed())

	// 1. Create all three items
	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items: []dg.Item{
			itemA, itemB, itemC,
		},
	})

	r := rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(itemA).To(BeCreated().After(itemC))
	t.Expect(itemB).To(BeCreated().After(itemC))
	t.Expect(itemC).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(3))
	t.Expect(status.NewCurrentState).ToNot(BeNil())

	current := status.NewCurrentState
	t.Expect(current.Name()).To(Equal(intent.Name()))
	t.Expect(current.Description()).To(Equal(intent.Description()))
	t.Expect(current.Items(true).Len()).To(Equal(3))
	t.Expect(current.SubGraphs().Len()).To(BeZero())

	item, state, path, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData := state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// 2. Modify itemC, dependent items A and B should remain unchanged
	//    (Dependency.Attributes.RecreateWhenModified is not set)
	itemC.modifiableAttrs.boolAttr = true
	intent.PutItem(itemC, nil)

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemC).To(BeModified())
	t.Expect(status.OperationLog).To(HaveLen(1))

	// 3. Delete itemC, dependent items A and B should be removed automatically.
	intent.DelItem(dg.Reference(itemC))

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeDeleted().Before(itemC))
	t.Expect(itemB).To(BeDeleted().Before(itemC))
	t.Expect(itemC).To(BeDeleted())
	t.Expect(status.OperationLog).To(HaveLen(3))

	_, _, _, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())
	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeFalse())
	_, _, _, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeFalse())
}

// Items: A, B, C
// Dependencies: A->C, B->C (with RecreateWhenModified)
func TestRecreateWhenModified(test *testing.T) {
	t := NewGomegaWithT(test)

	itemA := mockItem{
		name:            "A",
		itemType:        "type1",
		modifiableAttrs: mockItemAttrs{intAttr: 10, strAttr: "abc"},
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type2",
					ItemName: "C",
				},
				Attributes: dg.DependencyAttributes{
					RecreateWhenModified: true,
				},
			},
		},
	}
	itemB := mockItem{
		name:            "B",
		itemType:        "type1",
		modifiableAttrs: mockItemAttrs{boolAttr: true},
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type2",
					ItemName: "C",
				},
				Attributes: dg.DependencyAttributes{
					RecreateWhenModified: true,
				},
			},
		},
	}
	itemC := mockItem{
		name:     "C",
		itemType: "type2",
	}

	reg := &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())
	t.Expect(addConfigurator(reg, "type2")).To(Succeed())

	// 1. Create all three items
	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items: []dg.Item{
			itemA, itemB, itemC,
		},
	})

	r := rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(itemA).To(BeCreated().After(itemC))
	t.Expect(itemB).To(BeCreated().After(itemC))
	t.Expect(itemC).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(3))
	t.Expect(status.NewCurrentState).ToNot(BeNil())
	current := status.NewCurrentState

	// 2. Modify itemC, dependent items A and B should be re-created
	//    (ItemIsCreated.RecreateWhenModified is set)
	itemC.modifiableAttrs.boolAttr = true
	intent.PutItem(itemC, nil)

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeRecreated())
	t.Expect(itemB).To(BeRecreated())
	t.Expect(itemC).To(BeModified())
	t.Expect(itemA).To(BeDeleted().Before(itemC).IsModified())
	t.Expect(itemA).To(BeCreated().After(itemC).IsModified())
	t.Expect(itemB).To(BeDeleted().Before(itemC).IsModified())
	t.Expect(itemB).To(BeCreated().After(itemC).IsModified())
	// Recreate = 2 ops (Delete + Create)
	t.Expect(status.OperationLog).To(HaveLen(5))

	item, state, path, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData := state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationModify))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// 3. Put the same itemC, should not trigger Modify or Recreate
	intent.PutItem(itemC, nil)
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).ToNot(BeRecreated())
	t.Expect(itemB).ToNot(BeRecreated())
	t.Expect(itemC).ToNot(BeModified())
	t.Expect(status.OperationLog).To(BeEmpty())
}

// Items: A, B
// Dependencies: A->B
// Scenario: re-create of B should be surrounded by delete+create of A
func TestRecreate(test *testing.T) {
	t := NewGomegaWithT(test)

	itemA := mockItem{
		name:            "A",
		itemType:        "type1",
		modifiableAttrs: mockItemAttrs{intAttr: 10, strAttr: "abc"},
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type1",
					ItemName: "B",
				},
			},
		},
	}
	itemB := mockItem{
		name:        "B",
		itemType:    "type1",
		staticAttrs: mockItemAttrs{intAttr: 10},
	}

	reg := &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())

	// 1. Create both items
	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items: []dg.Item{
			itemA, itemB,
		},
	})

	r := rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(itemA).To(BeCreated().After(itemB))
	t.Expect(itemB).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(2))
	t.Expect(status.NewCurrentState).ToNot(BeNil())
	current := status.NewCurrentState

	// 2. Make modification to itemB which requires re-create
	itemB.staticAttrs.intAttr++
	intent.PutItem(itemB, nil)
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeRecreated())
	t.Expect(itemB).To(BeRecreated())
	t.Expect(itemA).To(BeDeleted().Before(itemB).IsRecreated())
	t.Expect(itemA).To(BeCreated().After(itemB).IsRecreated())
	t.Expect(status.OperationLog).To(HaveLen(4))

	item, state, path, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData := state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))
}

// Items: A, B, C
// Dependencies: A->B->C
func TestTransitiveDependencies(test *testing.T) {
	t := NewGomegaWithT(test)

	itemA := mockItem{
		name:     "A",
		itemType: "type1",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type2",
					ItemName: "B",
				},
			},
		},
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type2",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type3",
					ItemName: "C",
				},
			},
		},
	}
	itemC := mockItem{
		name:     "C",
		itemType: "type3",
	}

	reg := &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())
	t.Expect(addConfigurator(reg, "type2")).To(Succeed())
	t.Expect(addConfigurator(reg, "type3")).To(Succeed())

	// 1. Try to create only itemA and itemB at first
	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items: []dg.Item{
			itemA, itemB,
		},
	})

	r := rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(itemA).ToNot(BeCreated())
	t.Expect(itemB).ToNot(BeCreated())
	t.Expect(status.OperationLog).To(BeEmpty())
	t.Expect(status.NewCurrentState).ToNot(BeNil())
	current := status.NewCurrentState

	_, _, _, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())
	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeFalse())

	// 2. Now create itemC; itemA should be created transitively
	intent.PutItem(itemC, nil)
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeCreated().After(itemB))
	t.Expect(itemB).To(BeCreated().After(itemC))
	t.Expect(itemC).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(3))

	item, state, path, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData := state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// 3. Delete itemC, both itemA and itemB should be removed as well
	intent.DelItem(dg.Reference(itemC))
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeDeleted().Before(itemB))
	t.Expect(itemB).To(BeDeleted().Before(itemC))
	t.Expect(itemC).To(BeDeleted())
	t.Expect(status.OperationLog).To(HaveLen(3))

	_, _, _, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())
	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeFalse())
	_, _, _, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeFalse())
}

// Items: A, B
// Dependencies: A->B, A->C (but C is never created)
func TestUnsatisfiedDependency(test *testing.T) {
	t := NewGomegaWithT(test)

	itemA := mockItem{
		name:     "A",
		itemType: "type1",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type2",
					ItemName: "B",
				},
			},
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type2",
					ItemName: "C",
				},
			},
		},
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type2",
	}

	reg := &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())
	t.Expect(addConfigurator(reg, "type2")).To(Succeed())

	// 1. Intention is to have both A and B, but only B has satisfied dependencies
	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items: []dg.Item{
			itemA, itemB,
		},
	})

	r := rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(itemA).ToNot(BeCreated())
	t.Expect(itemB).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(1))
	t.Expect(status.NewCurrentState).ToNot(BeNil())
	current := status.NewCurrentState

	_, _, _, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())

	item, state, path, exists := current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData := state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// 2. Remove both items, NOOP for A
	intent.DelItem(dg.Reference(itemA))
	intent.DelItem(dg.Reference(itemB))
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).ToNot(BeDeleted())
	t.Expect(itemB).To(BeDeleted())
	t.Expect(status.OperationLog).To(HaveLen(1))

	_, _, _, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())

	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeFalse())
}

// Items: A, B
// Dependencies: A->B (with MustSatisfy defined to check the content of B)
func TestMustSatisfy(test *testing.T) {
	t := NewGomegaWithT(test)

	const magicValue = 42
	itemA := mockItem{
		name:     "A",
		itemType: "type1",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type1",
					ItemName: "B",
				},
				MustSatisfy: func(item dg.Item) bool {
					return item.(mockItem).modifiableAttrs.intAttr == magicValue
				},
			},
		},
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type1",
	}

	reg := &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())

	// 1. Intention is to have both A and B, but MustSatisfy of A fails for B
	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items: []dg.Item{
			itemA, itemB,
		},
	})

	r := rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(itemA).ToNot(BeCreated())
	t.Expect(itemB).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(1))
	t.Expect(status.NewCurrentState).ToNot(BeNil())
	current := status.NewCurrentState

	_, _, _, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())

	item, state, path, exists := current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData := state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// 2. Modify itemB, it should now satisfy itemA dependency
	itemB.modifiableAttrs.intAttr = magicValue
	intent.PutItem(itemB, nil)

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeCreated().After(itemB).IsModified())
	t.Expect(itemB).To(BeModified())
	t.Expect(status.OperationLog).To(HaveLen(2))

	item, state, path, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationModify))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))
}

// 3 scenarios where dependencies change with Modify.
func TestModifiedDependencies(test *testing.T) {
	t := NewGomegaWithT(test)

	// Scenario 1
	// Items: A, B, C
	// Dependencies: initially A->B, then A->C
	itemA := mockItem{
		name:     "A",
		itemType: "type1",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type2",
					ItemName: "B",
				},
			},
		},
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type2",
	}
	itemC := mockItem{
		name:     "C",
		itemType: "type2",
	}

	reg := &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())
	t.Expect(addConfigurator(reg, "type2")).To(Succeed())

	// 1.1 Create itemA and itemB at first
	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items: []dg.Item{
			itemA, itemB,
		},
	})

	r := rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(itemA).To(BeCreated().After(itemB))
	t.Expect(itemB).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(2))
	t.Expect(status.NewCurrentState).ToNot(BeNil())
	current := status.NewCurrentState

	item, state, path, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData := state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// 1.2. Modify itemA such then it now depends on non-existing itemC
	itemA.deps = []dg.Dependency{
		{
			RequiredItem: dg.ItemRef{
				ItemType: "type2",
				ItemName: "C",
			},
		},
	}
	intent.PutItem(itemA, nil)
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeDeleted())
	t.Expect(status.OperationLog).To(HaveLen(1))

	_, _, _, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())
	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())

	// 1.3 Create itemC and the pending itemA
	intent.PutItem(itemC, nil)
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeCreated().After(itemC))
	t.Expect(itemC).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(2))

	item, state, path, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())

	item, state, path, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// 1.4 Remove itemB; should have no effect on itemA
	intent.DelItem(dg.Reference(itemB))
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemB).To(BeDeleted())
	t.Expect(status.OperationLog).To(HaveLen(1))

	_, _, _, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeFalse())
	_, _, _, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())

	// Scenario 2
	// Items: A, B - changed to A', B'
	// Dependencies: A->B, then A'->B' (A must be recreated, there is no other way)
	const (
		magicValue1 = 42
		magicValue2 = 53
	)
	itemA = mockItem{
		name:     "A",
		itemType: "type1",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type1",
					ItemName: "B",
				},
				MustSatisfy: func(item dg.Item) bool {
					return item.(mockItem).modifiableAttrs.intAttr == magicValue1
				},
			},
		},
	}
	itemB = mockItem{
		name:     "B",
		itemType: "type1",
		modifiableAttrs: mockItemAttrs{
			intAttr: magicValue1,
		},
	}

	reg = &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())

	// 2.1. Create both items
	intent = dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items: []dg.Item{
			itemA, itemB,
		},
	})

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(itemA).To(BeCreated())
	t.Expect(itemB).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(2))
	t.Expect(status.NewCurrentState).ToNot(BeNil())
	current = status.NewCurrentState

	_, _, _, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())

	// 2.2. Modify both items - dependency is also updated
	// However, because modifications are done one after the other, itemA will be recreated.
	itemA.deps = []dg.Dependency{
		{
			RequiredItem: dg.ItemRef{
				ItemType: "type1",
				ItemName: "B",
			},
			MustSatisfy: func(item dg.Item) bool {
				return item.(mockItem).modifiableAttrs.intAttr == magicValue2
			},
		},
	}
	intent.PutItem(itemA, nil)
	itemB.modifiableAttrs.intAttr = magicValue2
	intent.PutItem(itemB, nil)

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeDeleted().Before(itemB).IsModified())
	t.Expect(itemB).To(BeModified())
	t.Expect(itemA).To(BeCreated().After(itemB).IsModified())
	t.Expect(status.OperationLog).To(HaveLen(3))

	item, state, path, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationModify))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// Scenario 3
	// Items: initially A, B, C; later A' (modified A) and C (B removed)
	// Dependencies: A->B, A'->C
	itemA = mockItem{
		name:     "A",
		itemType: "type1",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type2",
					ItemName: "B",
				},
			},
		},
	}
	itemB = mockItem{
		name:     "B",
		itemType: "type2",
	}
	itemC = mockItem{
		name:     "C",
		itemType: "type2",
	}

	reg = &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())
	t.Expect(addConfigurator(reg, "type2")).To(Succeed())

	// 3.1. Create all items
	intent = dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items: []dg.Item{
			itemA, itemB, itemC,
		},
	})

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(itemA).To(BeCreated().After(itemB))
	t.Expect(itemB).To(BeCreated())
	t.Expect(itemC).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(3))
	t.Expect(status.NewCurrentState).ToNot(BeNil())
	current = status.NewCurrentState

	_, _, _, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	_, _, _, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())

	// 3.2. Delete itemB but also modify itemA to depend on itemC now
	itemA.deps = []dg.Dependency{
		{
			RequiredItem: dg.ItemRef{
				ItemType: "type2",
				ItemName: "C",
			},
		},
	}
	intent.PutItem(itemA, nil)
	intent.DelItem(dg.Reference(itemB))

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeModified().Before(itemB).IsDeleted())
	t.Expect(itemB).To(BeDeleted())
	t.Expect(status.OperationLog).To(HaveLen(2))

	item, state, path, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationModify))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeFalse())

	item, state, path, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))
}

// Items (grouped with subgraphs): [A, B, [C, D]]
// Dependencies: C->A, D->B
func TestSubGraphs(test *testing.T) {
	t := NewGomegaWithT(test)

	itemA := mockItem{
		name:     "A",
		itemType: "type1",
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type1",
	}
	itemC := mockItem{
		name:     "C",
		itemType: "type2",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type1",
					ItemName: "A",
				},
			},
		},
	}
	itemD := mockItem{
		name:     "D",
		itemType: "type2",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type1",
					ItemName: "B",
				},
			},
		},
	}

	reg := &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())
	t.Expect(addConfigurator(reg, "type2")).To(Succeed())

	// 1. Create graph with subgraphs
	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Subgraphs: []dg.InitArgs{
			{
				Name:        "SubGraph",
				Description: "SubGraph inside TestGraph",
				Items:       []dg.Item{itemA, itemB},
				Subgraphs: []dg.InitArgs{
					{
						Name:        "NestedSubGraph",
						Description: "SubGraph inside SubGraph",
						Items:       []dg.Item{itemC, itemD},
					},
				},
			},
		},
	})

	r := rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(itemA).To(BeCreated())
	t.Expect(itemB).To(BeCreated())
	t.Expect(itemC).To(BeCreated().After(itemA))
	t.Expect(itemD).To(BeCreated().After(itemB))
	t.Expect(status.OperationLog).To(HaveLen(4))
	t.Expect(status.NewCurrentState).ToNot(BeNil())
	current := status.NewCurrentState

	t.Expect(current.SubGraphs().Len()).To(Equal(1))
	subGraph := current.SubGraph("SubGraph")
	t.Expect(subGraph).ToNot(BeNil())
	t.Expect(subGraph.Description()).To(Equal("SubGraph inside TestGraph"))
	t.Expect(subGraph.SubGraphs().Len()).To(Equal(1))
	t.Expect(subGraph.Items(false).Len()).To(Equal(2))
	nestedSubGraph := subGraph.SubGraph("NestedSubGraph")
	t.Expect(nestedSubGraph).ToNot(BeNil())
	t.Expect(nestedSubGraph.Description()).To(Equal("SubGraph inside SubGraph"))
	t.Expect(nestedSubGraph.SubGraphs().Len()).To(BeZero())
	t.Expect(nestedSubGraph.Items(false).Len()).To(Equal(2))

	item, state, path, exists := subGraph.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData := state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = subGraph.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = nestedSubGraph.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = nestedSubGraph.Item(dg.Reference(itemD))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemD))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// 2. Change content of the subgraph
	subGraph = intent.SubGraph("SubGraph")
	subGraphRW := intent.EditSubGraph(subGraph)
	itemA.staticAttrs.strAttr = "modified"
	subGraphRW.PutItem(itemA, nil)
	subGraphRW.DelItem(dg.Reference(itemB))
	subGraphRW.SetDescription("Modified description")

	// Reconcile only the subgraph
	subGraph = current.SubGraph("SubGraph")
	subGraphRW = current.EditSubGraph(subGraph)
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), subGraphRW, intent.SubGraph("SubGraph"))
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(subGraphRW))
	t.Expect(subGraphRW.ParentGraph()).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeRecreated())
	t.Expect(itemB).To(BeDeleted())
	t.Expect(itemC).To(BeRecreated())
	t.Expect(itemC).To(BeDeleted().Before(itemA).IsRecreated())
	t.Expect(itemC).To(BeCreated().After(itemA).IsRecreated())
	t.Expect(itemD).To(BeDeleted().Before(itemB))
	t.Expect(status.OperationLog).To(HaveLen(6))

	t.Expect(current.SubGraphs().Len()).To(Equal(1))
	subGraph = current.SubGraph("SubGraph")
	t.Expect(subGraph).ToNot(BeNil())
	t.Expect(subGraph.Description()).To(Equal("Modified description"))
	t.Expect(subGraph.SubGraphs().Len()).To(Equal(1))
	t.Expect(subGraph.Items(false).Len()).To(Equal(1))
	nestedSubGraph = subGraph.SubGraph("NestedSubGraph")
	t.Expect(nestedSubGraph).ToNot(BeNil())
	t.Expect(nestedSubGraph.Description()).To(Equal("SubGraph inside SubGraph"))
	t.Expect(nestedSubGraph.SubGraphs().Len()).To(BeZero())
	t.Expect(nestedSubGraph.Items(false).Len()).To(Equal(1))

	item, state, path, exists = subGraph.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	_, _, _, exists = subGraph.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeFalse())

	item, state, path, exists = nestedSubGraph.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))
	_, _, path, _ = subGraph.Item(dg.Reference(itemC))
	t.Expect(path).To(Equal(dg.SubGraphPath{}.Append("NestedSubGraph")))

	_, _, _, exists = nestedSubGraph.Item(dg.Reference(itemD))
	t.Expect(exists).To(BeFalse())

	// 3. Apply the same content again
	subGraph = current.SubGraph("SubGraph")
	subGraphRW = current.EditSubGraph(subGraph)
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), subGraphRW, intent.SubGraph("SubGraph"))
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(subGraphRW))
	t.Expect(subGraphRW.ParentGraph()).To(BeIdenticalTo(current))
	t.Expect(status.OperationLog).To(BeEmpty())

	// 4. Remove entire (nested) subgraph - reconcile against nil intent
	subGraph = current.SubGraph("SubGraph")
	nestedSubGraph = subGraph.SubGraph("NestedSubGraph")
	nestedSubGraphRW := current.EditSubGraph(nestedSubGraph)
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), nestedSubGraphRW, nil)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeNil())
	t.Expect(itemC).To(BeDeleted())
	t.Expect(status.OperationLog).To(HaveLen(1))

	t.Expect(current.SubGraphs().Len()).To(Equal(1))
	subGraph = current.SubGraph("SubGraph")
	t.Expect(subGraph).ToNot(BeNil())
	t.Expect(subGraph.Description()).To(Equal("Modified description"))
	t.Expect(subGraph.SubGraphs().Len()).To(BeZero())
	t.Expect(subGraph.Items(true).Len()).To(Equal(1))

	_, _, _, exists = subGraph.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	_, _, _, exists = subGraph.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeFalse())

	// 6. Move itemA to another subGraph (the top-level one)
	intent = dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items:       []dg.Item{itemA},
	})

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(status.OperationLog).To(BeEmpty())

	t.Expect(current.SubGraphs().Len()).To(BeZero())
	t.Expect(current.Items(false).Len()).To(Equal(1))

	item, state, path, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))
}

// Items (grouped with subgraphs): [A [B]]
// Dependencies: A->B
func TestRecreateFromOutsideOfSelection(test *testing.T) {
	t := NewGomegaWithT(test)

	itemA := mockItem{
		name:     "A",
		itemType: "type1",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type2",
					ItemName: "B",
				},
			},
		},
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type2",
	}

	reg := &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())
	t.Expect(addConfigurator(reg, "type2")).To(Succeed())

	// 1. Create graph with subgraphs
	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items:       []dg.Item{itemA},
		Subgraphs: []dg.InitArgs{
			{
				Name:        "SubGraph",
				Description: "SubGraph inside TestGraph",
				Items:       []dg.Item{itemB},
			},
		},
	})

	r := rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(itemA).To(BeCreated().After(itemB))
	t.Expect(itemB).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(2))
	t.Expect(status.NewCurrentState).ToNot(BeNil())
	current := status.NewCurrentState

	// 2. Make modification to itemB which requires re-create
	//    Reconcile only subgraph with item B - still the item A should be recreated as well.
	itemB.staticAttrs.intAttr++
	itemBPath := dg.NewSubGraphPath("SubGraph")
	dg.PutItemInto(intent, itemB, nil, itemBPath)
	r = rec.New(reg)
	subGraph := current.SubGraph("SubGraph")
	subGraphRW := current.EditSubGraph(subGraph)
	status = r.Reconcile(context.Background(), subGraphRW, intent.SubGraph("SubGraph"))
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(subGraphRW))
	t.Expect(itemA).To(BeRecreated())
	t.Expect(itemB).To(BeRecreated())
	t.Expect(itemA).To(BeDeleted().Before(itemB).IsRecreated())
	t.Expect(itemA).To(BeCreated().After(itemB).IsRecreated())
	t.Expect(status.OperationLog).To(HaveLen(4))

	item, state, path, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData := state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Compare(itemBPath)).To(Equal(0))
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))
}

// Items: A, B, External (obviously external item)
// Dependencies: A->External, B->External
func TestExternalItems(test *testing.T) {
	t := NewGomegaWithT(test)

	const magicValue = 42
	itemA := mockItem{
		name:     "A",
		itemType: "type1",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type2",
					ItemName: "External",
				},
				Attributes: dg.DependencyAttributes{
					RecreateWhenModified:  true,
					AutoDeletedByExternal: true,
				},
			},
		},
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type1",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type2",
					ItemName: "External",
				},
				MustSatisfy: func(item dg.Item) bool {
					return item.(mockItem).modifiableAttrs.intAttr == magicValue
				},
			},
		},
	}
	itemExt := mockItem{
		name:       "External",
		itemType:   "type2",
		isExternal: true,
		modifiableAttrs: mockItemAttrs{
			intAttr: magicValue,
		},
	}
	reg := &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())
	// No configurator for type2 - those items are created externally

	// 1. The intention is to have both itemA and itemB, but "External" is still missing
	//    (in the current state)
	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items: []dg.Item{
			itemA, itemB, itemExt, /* it is desired for "External" to exist */
		},
	})

	r := rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(itemA).ToNot(BeCreated())
	t.Expect(itemB).ToNot(BeCreated())
	t.Expect(itemExt).ToNot(BeCreated())
	t.Expect(status.OperationLog).To(BeEmpty())
	t.Expect(status.NewCurrentState).ToNot(BeNil())
	current := status.NewCurrentState

	_, _, _, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())
	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeFalse())
	_, _, _, exists = current.Item(dg.Reference(itemExt))
	t.Expect(exists).To(BeFalse())

	// 2. External item was created
	current.PutItem(itemExt, &rec.ItemStateData{
		State:         rec.ItemStateCreated,
		LastOperation: rec.OperationCreate,
		LastError:     nil,
	})
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeCreated())
	t.Expect(itemB).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(2))

	item, state, path, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData := state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// 3. External item was modified - itemA should be recreated, itemB does not have satisfied dep anymore
	itemExt.modifiableAttrs.intAttr = 0
	current.PutItem(itemExt, &rec.ItemStateData{
		State:              rec.ItemStateCreated,
		LastOperation:      rec.OperationModify,
		LastError:          nil,
		ExternallyModified: true, // to inform the Reconciler about the modification
	})
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeRecreated())
	t.Expect(itemB).To(BeDeleted())
	t.Expect(status.OperationLog).To(HaveLen(3))

	item, state, path, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeFalse())

	_, state, _, exists = current.Item(dg.Reference(itemExt))
	t.Expect(exists).To(BeTrue())
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.ExternallyModified).To(BeFalse()) // was reset by Reconciler

	// 4. External item was deleted - itemA is configured with AutoDeletedByExternal, which means
	//    that it is automatically removed in this case.
	current.DelItem(dg.Reference(itemExt))
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(status.OperationLog).To(BeEmpty())

	_, _, _, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())
	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeFalse())
	_, _, _, exists = current.Item(dg.Reference(itemExt))
	t.Expect(exists).To(BeFalse())
}

// Items: A, B, C
// Dependencies: A->B->C
// Scenario: some Create/Modify/Delete operations fail
func TestFailures(test *testing.T) {
	t := NewGomegaWithT(test)

	itemA := mockItem{
		name:     "A",
		itemType: "type1",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type1",
					ItemName: "B",
				},
			},
		},
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type1",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type2",
					ItemName: "C",
				},
			},
		},
	}
	itemC := mockItem{
		name:     "C",
		itemType: "type2",
	}

	reg := &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())
	t.Expect(addConfigurator(reg, "type2")).To(Succeed())

	// 1. itemB will fail to be created
	itemB.failToCreate = true
	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items: []dg.Item{
			itemA, itemB, itemC,
		},
	})

	r := rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).ToNot(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(itemA).ToNot(BeCreated())
	t.Expect(itemB).To(BeCreated().WithError("failed to create"))
	t.Expect(itemC).To(BeCreated().Before(itemB))
	t.Expect(status.OperationLog).To(HaveLen(2))
	t.Expect(status.NewCurrentState).ToNot(BeNil())
	current := status.NewCurrentState

	_, _, _, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())

	item, state, path, exists := current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData := state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(MatchError("failed to create"))
	t.Expect(stateData.State).To(Equal(rec.ItemStateFailure))

	item, state, path, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// 2. Next attempt to create itemB is successful
	itemB.failToCreate = false
	itemB.failToDelete = true // prepare for scenario 4.
	itemB.modifiableAttrs.boolAttr = true
	intent.PutItem(itemB, nil)

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeCreated().WithoutPrevError())
	t.Expect(itemA).To(BeCreated().After(itemB))
	t.Expect(itemB).To(BeCreated().WithPrevError("failed to create"))
	t.Expect(status.OperationLog).To(HaveLen(2))

	item, state, path, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// 3. Simulate failure to modify C
	itemC.failToCreate = true
	itemC.modifiableAttrs.strAttr = "modified"
	intent.PutItem(itemC, nil)

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).ToNot(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemC).To(BeModified().WithError("failed to modify"))
	t.Expect(status.OperationLog).To(HaveLen(1))

	item, state, path, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	itemC.modifiableAttrs.strAttr = "" // not applied
	t.Expect(item).To(BeMockItem(itemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationModify))
	t.Expect(stateData.LastError).To(MatchError("failed to modify"))
	t.Expect(stateData.State).To(Equal(rec.ItemStateFailure))

	// 4. Simulate failure to re-create itemB (delete fails)
	//    But the next attempt to modify itemC is successful.
	itemB.staticAttrs.strAttr = "modified"
	intent.PutItem(itemB, nil)
	itemC.modifiableAttrs.strAttr = "modified"
	itemC.failToCreate = false
	intent.PutItem(itemC, nil)

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).ToNot(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeDeleted().Before(itemB))
	t.Expect(itemB).To(BeDeleted().WithError("failed to delete"))
	t.Expect(itemC).To(BeModified().WithPrevError("failed to modify"))
	t.Expect(status.OperationLog).To(HaveLen(3))

	_, _, _, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	itemB.staticAttrs.strAttr = "" // not applied
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationDelete))
	t.Expect(stateData.LastError).To(MatchError("failed to delete"))
	t.Expect(stateData.State).To(Equal(rec.ItemStateFailure))

	item, state, path, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationModify))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// 5. Fix itemB, recover itemA
	itemB.staticAttrs.strAttr = ""
	itemB.modifiableAttrs.strAttr = "modified without re-create"
	itemB.failToDelete = false
	intent.PutItem(itemB, nil)
	itemA.failToDelete = true // prepare for scenario 6
	intent.PutItem(itemA, nil)
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeCreated().After(itemB).IsModified())
	t.Expect(itemB).To(BeModified().WithPrevError("failed to delete"))
	t.Expect(status.OperationLog).To(HaveLen(2))

	item, state, path, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	itemB.staticAttrs.strAttr = "" // not applied
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationModify))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// 6. Try to remove itemB, but actually a failure to remove itemA
	//    will put this on hold.
	intent.DelItem(dg.Reference(itemB))
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).ToNot(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).To(BeDeleted().WithError("failed to delete"))
	t.Expect(status.OperationLog).To(HaveLen(1))

	item, state, path, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationDelete))
	t.Expect(stateData.LastError).To(MatchError("failed to delete"))
	t.Expect(stateData.State).To(Equal(rec.ItemStateFailure))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	itemB.staticAttrs.strAttr = "" // not applied
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationModify))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))
}

func waitForAsyncOps(t *GomegaWithT, opCount int) {
	waitFor := asyncOpDuration + 2*time.Second
	var graphName string
	t.Eventually(status.ReadyToResume, waitFor).Should(Receive(&graphName))
	t.Expect(graphName).To(Equal("TestGraph"))

	if opCount > 1 {
		time.Sleep(2 * time.Second) // enough for everything to finalize
	}

	for i := 1; i < opCount; i++ {
		select {
		case graphName = <-status.ReadyToResume:
			t.Expect(graphName).To(Equal("TestGraph"))
		default:
			// Signals have coalesced.
		}
	}
}

// Items: A, B, C, D
// Dependencies: A->B->C
// Several scenarios with asynchronous operations.
func TestAsyncOperations(test *testing.T) {
	t := NewGomegaWithT(test)

	itemA := mockItem{
		name:     "A",
		itemType: "type1",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type1",
					ItemName: "B",
				},
			},
		},
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type1",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type2",
					ItemName: "C",
				},
			},
		},
	}
	itemC := mockItem{
		name:     "C",
		itemType: "type2",
	}
	itemD := mockItem{
		name:     "D",
		itemType: "type2",
	}

	reg := &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())
	t.Expect(addConfigurator(reg, "type2")).To(Succeed())

	// 1. Try to create all items, but Create for itemB will run asynchronously.
	itemB.asyncCreate = true
	itemA.asyncDelete = true // prepare for scenario 5
	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items: []dg.Item{
			itemA, itemB, itemC, itemD,
		},
	})

	r := rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeTrue())
	t.Expect(status.ReadyToResume).ToNot(BeNil())
	t.Expect(itemA).ToNot(BeCreated())
	t.Expect(itemB).To(BeingCreated().After(itemC).IsCreated())
	t.Expect(itemC).To(BeCreated())
	t.Expect(itemD).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(3))
	t.Expect(status.NewCurrentState).ToNot(BeNil())
	current := status.NewCurrentState

	_, _, _, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())

	item, state, path, exists := current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData := state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationUnknown))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreating))

	item, state, path, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemD))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemD))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	waitForAsyncOps(t, 1)

	// 2. Resume reconciliation now that Create() for itemB finalized
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(status.ReadyToResume).To(BeNil())
	t.Expect(itemA).To(BeCreated().After(itemB))
	t.Expect(itemB).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(2))

	item, state, path, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	// 3. Modify itemC asynchronously.
	itemC.modifiableAttrs.strAttr = "modified"
	itemC.asyncCreate = true
	intent.PutItem(itemC, nil)

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeTrue())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(status.ReadyToResume).ToNot(BeNil())
	t.Expect(itemC).To(BeingModified())
	t.Expect(status.OperationLog).To(HaveLen(1))

	item, state, path, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	currentItemC := itemC
	currentItemC.modifiableAttrs.strAttr = "" // not yet applied
	t.Expect(item).To(BeMockItem(currentItemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateModifying))

	// 4. Modify itemB. But since its dependency itemC is still being modified,
	//    this will be done later.
	itemB.modifiableAttrs.strAttr = "modified"
	itemB.asyncCreate = false
	itemB.asyncDelete = true // prepare for scenario 6
	intent.PutItem(itemB, nil)

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeTrue())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(status.ReadyToResume).ToNot(BeNil())
	t.Expect(status.OperationLog).To(BeEmpty())

	waitForAsyncOps(t, 2)

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(status.ReadyToResume).To(BeNil())
	t.Expect(itemB).To(BeModified().After(itemC))
	t.Expect(itemC).To(BeModified())
	t.Expect(status.OperationLog).To(HaveLen(2))

	// 5. Delete itemC, but first itemB and itemA should be removed.
	//    Delete of itemA will run asynchronously, thus blocking delete of itemB and itemC
	intent.DelItem(dg.Reference(itemC))

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeTrue())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(status.ReadyToResume).ToNot(BeNil())
	t.Expect(itemA).To(BeingDeleted())
	t.Expect(status.OperationLog).To(HaveLen(1))

	item, state, path, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateDeleting))

	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	_, _, _, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())

	waitForAsyncOps(t, 1)

	// 6. Resume reconciliation now that Delete() for itemA finalized.
	//    Next itemB will be deleted, but also asynchronously.
	//    Moreover, intentional state for itemD changed and needs to be applied through (async) Modify().
	itemD.asyncCreate = true
	itemD.modifiableAttrs.strAttr = "modified"
	intent.PutItem(itemD, nil)

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeTrue())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(status.ReadyToResume).ToNot(BeNil())
	t.Expect(itemA).To(BeDeleted())
	t.Expect(itemB).To(BeingDeleted())
	t.Expect(itemD).To(BeingModified())
	t.Expect(status.OperationLog).To(HaveLen(3))

	_, _, _, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationModify))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateDeleting))

	item, state, path, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationModify))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemD))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	currentItemD := itemD
	currentItemD.modifiableAttrs.strAttr = "" // not yet applied
	t.Expect(item).To(BeMockItem(currentItemD))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateModifying))

	waitForAsyncOps(t, 2)

	// 7. Resume reconciliation now that all async ops are done.
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(status.ReadyToResume).To(BeNil())
	t.Expect(itemB).To(BeDeleted().Before(itemC))
	t.Expect(itemC).To(BeDeleted())
	t.Expect(itemD).To(BeModified())
	t.Expect(status.OperationLog).To(HaveLen(3))

	_, _, _, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())

	_, _, _, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeFalse())

	_, _, _, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeFalse())

	item, state, path, exists = current.Item(dg.Reference(itemD))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemD))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationModify))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))
}

// Items: A, B, C, D
// Dependencies: A->B->C
// Scenario: Asynchronous operations with failures.
func TestAsyncFailures(test *testing.T) {
	t := NewGomegaWithT(test)

	itemA := mockItem{
		name:     "A",
		itemType: "type1",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type1",
					ItemName: "B",
				},
			},
		},
	}
	itemB := mockItem{
		name:     "B",
		itemType: "type1",
		deps: []dg.Dependency{
			{
				RequiredItem: dg.ItemRef{
					ItemType: "type2",
					ItemName: "C",
				},
			},
		},
	}
	itemC := mockItem{
		name:     "C",
		itemType: "type2",
	}

	itemD := mockItem{
		name:     "D",
		itemType: "type2",
	}

	reg := &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())
	t.Expect(addConfigurator(reg, "type2")).To(Succeed())

	// 1. itemB and itemD will fail to be created asynchronously
	itemB.failToCreate = true
	itemB.asyncCreate = true
	itemD.failToCreate = true
	itemD.asyncCreate = true
	itemA.failToCreate = true // prepare for scenario 4.
	itemA.asyncCreate = true
	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items: []dg.Item{
			itemA, itemB, itemC, itemD,
		},
	})

	r := rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeTrue())
	t.Expect(status.ReadyToResume).ToNot(BeNil())
	t.Expect(itemA).ToNot(BeCreated())
	t.Expect(itemB).To(BeingCreated().After(itemC).IsCreated())
	t.Expect(itemC).To(BeCreated())
	t.Expect(itemD).To(BeingCreated())
	t.Expect(status.OperationLog).To(HaveLen(3))
	t.Expect(status.NewCurrentState).ToNot(BeNil())
	current := status.NewCurrentState

	_, _, _, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())

	item, state, path, exists := current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData := state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationUnknown))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreating))

	item, state, path, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	item, state, path, exists = current.Item(dg.Reference(itemD))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemD))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationUnknown))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreating))

	waitForAsyncOps(t, 2)

	// 2. Resume reconciliation now that Create() for itemB and itemD finalized (with errors)
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).ToNot(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(itemA).ToNot(BeCreated())
	t.Expect(itemB).To(BeCreated().WithError("failed to create"))
	t.Expect(itemD).To(BeCreated().WithError("failed to create"))
	t.Expect(status.OperationLog).To(HaveLen(2))
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))

	_, _, _, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeFalse())

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(MatchError("failed to create"))
	t.Expect(stateData.State).To(Equal(rec.ItemStateFailure))

	item, state, path, exists = current.Item(dg.Reference(itemD))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemD))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(MatchError("failed to create"))
	t.Expect(stateData.State).To(Equal(rec.ItemStateFailure))

	// 2. Next attempt to create itemB is successful and create for A starts
	itemB.failToCreate = false
	itemB.failToDelete = true // prepare for scenario 7.
	itemB.asyncDelete = true
	itemB.modifiableAttrs.boolAttr = true
	intent.PutItem(itemB, nil)

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeTrue())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(status.ReadyToResume).ToNot(BeNil())
	t.Expect(itemB).To(BeingCreated())
	t.Expect(status.OperationLog).To(HaveLen(1))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(MatchError("failed to create"))
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreating))

	waitForAsyncOps(t, 1)

	// 3. Resume reconciliation now that Create() for itemB finalized
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeTrue())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(status.ReadyToResume).ToNot(BeNil())
	t.Expect(itemA).To(BeingCreated().After(itemB))
	t.Expect(itemB).To(BeCreated())
	t.Expect(status.OperationLog).To(HaveLen(2))

	item, state, path, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationUnknown))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreating))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreated))

	waitForAsyncOps(t, 1)

	// 4. Resume reconciliation now that Create() for itemA finalized (with error)
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).ToNot(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(itemA).To(BeCreated().WithError("failed to create"))
	t.Expect(status.OperationLog).To(HaveLen(1))
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))

	item, state, path, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(MatchError("failed to create"))
	t.Expect(stateData.State).To(Equal(rec.ItemStateFailure))

	// 5. Simulate failure to modify C asynchronously
	itemC.failToCreate = true
	itemC.modifiableAttrs.strAttr = "modified"
	itemC.asyncCreate = true
	intent.PutItem(itemC, nil)

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeTrue())
	t.Expect(status.ReadyToResume).ToNot(BeNil())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemC).To(BeingModified())
	t.Expect(status.OperationLog).To(HaveLen(1))

	item, state, path, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	itemC.modifiableAttrs.strAttr = "" // not applied
	t.Expect(item).To(BeMockItem(itemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateModifying))

	waitForAsyncOps(t, 1)

	// 6. Resume reconciliation now that Modify() for itemC finalized (with error)
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).ToNot(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(status.ReadyToResume).To(BeNil())
	t.Expect(itemC).To(BeModified().WithError("failed to modify"))
	t.Expect(status.OperationLog).To(HaveLen(1))

	item, state, path, exists = current.Item(dg.Reference(itemC))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	itemC.modifiableAttrs.strAttr = "" // not applied
	t.Expect(item).To(BeMockItem(itemC))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationModify))
	t.Expect(stateData.LastError).To(MatchError("failed to modify"))
	t.Expect(stateData.State).To(Equal(rec.ItemStateFailure))

	// 7. Simulate failure to re-create itemB (asynchronous delete fails)
	prevItemB := itemB
	itemB.staticAttrs.strAttr = "modified"
	intent.PutItem(itemB, nil)
	intent.PutItem(itemC, nil) // give up on trying to modify C

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeTrue())
	t.Expect(status.ReadyToResume).ToNot(BeNil())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(itemA).ToNot(BeDeleted()) // create failed
	t.Expect(itemB).To(BeingDeleted())
	t.Expect(status.OperationLog).To(HaveLen(1))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(prevItemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateDeleting))

	waitForAsyncOps(t, 1)

	// 8. Resume reconciliation now that async op has finalized
	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).ToNot(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(status.ReadyToResume).To(BeNil())
	t.Expect(itemB).To(BeDeleted().WithError("failed to delete"))
	t.Expect(status.OperationLog).To(HaveLen(1))

	item, state, path, exists = current.Item(dg.Reference(itemB))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	itemB.staticAttrs.strAttr = "" // not applied
	t.Expect(item).To(BeMockItem(itemB))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationDelete))
	t.Expect(stateData.LastError).To(MatchError("failed to delete"))
	t.Expect(stateData.State).To(Equal(rec.ItemStateFailure))
}

// Items: A
// No dependencies
func TestCancelAsyncOperation(test *testing.T) {
	t := NewGomegaWithT(test)

	itemA := mockItem{
		name:        "A",
		itemType:    "type1",
		asyncCreate: true,
	}

	reg := &rec.DefaultRegistry{}
	t.Expect(addConfigurator(reg, "type1")).To(Succeed())

	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
		Items:       []dg.Item{itemA},
	})

	r := rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	t.Expect(status.Err).To(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeTrue())
	t.Expect(status.ReadyToResume).ToNot(BeNil())
	t.Expect(itemA).To(BeingCreated())
	t.Expect(itemA).ToNot(BeingRecreated()) // just to use BeingRecreated at least once
	t.Expect(status.OperationLog).To(HaveLen(1))
	t.Expect(status.NewCurrentState).ToNot(BeNil())
	current := status.NewCurrentState

	item, state, path, exists := current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData := state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationUnknown))
	t.Expect(stateData.LastError).To(BeNil())
	t.Expect(stateData.State).To(Equal(rec.ItemStateCreating))

	// Cancel Create() of itemA.
	status.CancelAsyncOps()
	timeout := time.After(2 * time.Second)
	done := make(chan bool)
	go func() {
		status.WaitForAsyncOps()
		done <- true
	}()
	select {
	case <-timeout:
		test.Fatalf("Failed to cancel async op")
	case <-done:
	}

	waitFor := time.Second
	var graphName string
	t.Eventually(status.ReadyToResume, waitFor).Should(Receive(&graphName))
	t.Expect(graphName).To(Equal("TestGraph"))

	r = rec.New(reg)
	status = r.Reconcile(context.Background(), current, intent)
	t.Expect(status.Err).ToNot(BeNil())
	t.Expect(status.AsyncOpsInProgress).To(BeFalse())
	t.Expect(status.NewCurrentState).To(BeIdenticalTo(current))
	t.Expect(status.ReadyToResume).To(BeNil())
	t.Expect(itemA).To(BeCreated().WithError("failed to complete"))
	t.Expect(status.OperationLog).To(HaveLen(1))

	item, state, path, exists = current.Item(dg.Reference(itemA))
	t.Expect(exists).To(BeTrue())
	t.Expect(path.Len()).To(BeZero())
	t.Expect(item).To(BeMockItem(itemA))
	stateData = state.(*rec.ItemStateData)
	t.Expect(stateData).ToNot(BeNil())
	t.Expect(stateData.LastOperation).To(Equal(rec.OperationCreate))
	t.Expect(stateData.LastError).To(MatchError("failed to complete"))
	t.Expect(stateData.State).To(Equal(rec.ItemStateFailure))
}

func BenchmarkDepGraph100(b *testing.B) {
	for n := 0; n < b.N; n++ {
		err := perfTest(b, 100)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDepGraph1000(b *testing.B) {
	for n := 0; n < b.N; n++ {
		err := perfTest(b, 1000)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDepGraph10000(b *testing.B) {
	for n := 0; n < b.N; n++ {
		err := perfTest(b, 10000)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDepGraph100000(b *testing.B) {
	for n := 0; n < b.N; n++ {
		err := perfTest(b, 100000)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Perf test proves that the Reconciler.Reconcile() complexity is linear with respect
// to the number of nodes. Actually, it is O(V+E), but each node has only a constant
// number of edges in this benchmark, reflecting a realistic use-case.
func perfTest(_ *testing.B, numOfItems int) error {
	reg := &rec.DefaultRegistry{}
	err := addConfigurator(reg, "item-type")
	if err != nil {
		return err
	}

	intent := dg.New(dg.InitArgs{
		Name:        "TestGraph",
		Description: "Graph for testing",
	})
	const numOfDeps = 10
	for i := 0; i < numOfItems; i++ {
		deps := make([]dg.Dependency, 0, numOfDeps)
		for j := i + 1; j < numOfItems && j <= i+numOfDeps; j++ {
			deps = append(deps, dg.Dependency{
				RequiredItem: dg.ItemRef{
					ItemType: "item-type",
					ItemName: strconv.Itoa(j),
				},
			})
		}
		item := mockItem{
			name:     strconv.Itoa(i),
			itemType: "item-type",
			deps:     deps,
		}
		intent.PutItem(item, nil)
	}
	r := rec.New(reg)
	status = r.Reconcile(context.Background(), nil, intent)
	return status.Err
}
