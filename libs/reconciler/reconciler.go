// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	dg "github.com/lf-edge/eve/libs/depgraph"
)

// reconciler implements Reconciler API
type reconciler struct {
	CR ConfiguratorRegistry
}

// ctxKey is an unexported type for context keys defined in this package.
// This prevents collisions with keys defined in other packages.
type ctxKey int

const (
	opCtxKey ctxKey = iota
	mockRunCtxKey
)

// newOpCtx returns a new context to pass to Create/Delete/Modify.
func newOpCtx(ctx context.Context, opCtx *opCtx) context.Context {
	return context.WithValue(ctx, opCtxKey, opCtx)
}

// getOpCtx returns opCtx value stored in ctx.
func getOpCtx(ctx context.Context) *opCtx {
	return ctx.Value(opCtxKey).(*opCtx)
}

// mockRunAttrs : attributes for a mock reconciliation (see MockRun()).
type mockRunAttrs struct {
	// No attributes for now.
}

func errMissingConfigurator(item dg.Item) error {
	return fmt.Errorf("missing configurator for item: %s/%s",
		item.Type(), item.Name())
}

// Reconcile : run state reconciliation. The function makes state transitions
// (using Configurators) to get from the currentState (closer) to the intended
// state. The function updates the currentState graph to reflect all the performed
// changes.
func (r *reconciler) Reconcile(ctx context.Context,
	currentState dg.Graph, intendedState dg.GraphR) (status Status) {

	// Pre-process input arguments.
	if currentState == nil && intendedState == nil {
		return status
	}
	if currentState != nil && intendedState != nil {
		if currentState.Name() != intendedState.Name() {
			status.Err = fmt.Errorf("current/intended graph mismatch: %s vs. %s",
				currentState.Name(), intendedState.Name())
			return status
		}
	}
	if currentState == nil {
		currentState = dg.New(dg.InitArgs{
			Name:        intendedState.Name(),
			Description: intendedState.Description(),
		})
	}
	currentFullState := dg.GetGraphRoot(currentState)
	if currentFullState.PrivateData() == nil {
		currentFullState.PutPrivateData(newGraphCtx())
	}
	status.NewCurrentState = currentState
	if ctx == nil {
		ctx = context.Background()
	}

	// Prepare manager for asynchronous operations.
	graphCtx := currentFullState.PrivateData().(*graphCtx)
	asyncManager := graphCtx.asyncManager
	asyncManager.reconcileStarts()

	// Run state reconciliation.
	var errs []error
	r.syncUpdatedSubgraphs(currentState, intendedState)
	err := r.reconcileItems(ctx, asyncManager, currentState, intendedState, &status)
	if err != nil {
		errs = append(errs, err)
	}
	deleted := r.syncDeletedSubgraphs(currentState, intendedState)
	if deleted {
		status.NewCurrentState = nil
	}

	// Report about any asynchronous operations still running.
	status.AsyncOpsInProgress, status.ReadyToResume = asyncManager.reconcileEnds()
	if status.AsyncOpsInProgress {
		status.CancelAsyncOps = asyncManager.cancelOps
		status.WaitForAsyncOps = asyncManager.waitForOps
	}

	// Summarize all errors (if any) into status.Err
	for _, logEntry := range status.OperationLog {
		if logEntry.Err != nil {
			errs = append(errs, logEntry.Err)
		}
	}
	if len(errs) > 0 {
		var errMsgs []string
		for _, err := range errs {
			errMsgs = append(errMsgs, err.Error())
		}
		status.Err = errors.New(strings.Join(errMsgs, "; "))
	}

	// Order log entries by the start time of operations.
	// Async operations could be out of order.
	sort.Slice(status.OperationLog, func(i, j int) bool {
		return status.OperationLog[i].StartTime.Before(
			status.OperationLog[j].StartTime)
	})
	return status
}

// Update/create metadata (names and descriptions) of subgraphs which were
// updated/added into the intendedState.
func (r *reconciler) syncUpdatedSubgraphs(
	currentState dg.Graph, intendedState dg.GraphR) {
	if intendedState == nil {
		return
	}
	currentState.SetDescription(intendedState.Description())
	iter := intendedState.SubGraphs()
	for iter.Next() {
		intSubgraph := iter.SubGraph()
		var curSubgraph dg.Graph
		curSubgraphR := currentState.SubGraph(intSubgraph.Name())
		if curSubgraphR == nil {
			curSubgraph = dg.New(dg.InitArgs{Name: intSubgraph.Name()})
			currentState.PutSubGraph(curSubgraph)
		} else {
			curSubgraph = currentState.EditSubGraph(curSubgraphR)
		}
		r.syncUpdatedSubgraphs(curSubgraph, intSubgraph)
	}
}

// Delete metadata (names and descriptions) of subgraphs which were
// removed from the intendedState. Skip subgraphs which still contain some items.
func (r *reconciler) syncDeletedSubgraphs(
	currentState dg.Graph, intendedState dg.GraphR) (deleted bool) {
	var toDelete, toDescend []dg.Graph
	iter := currentState.SubGraphs()
	for iter.Next() {
		subgraph := iter.SubGraph()
		if intendedState == nil || intendedState.SubGraph(subgraph.Name()) == nil {
			// Do not delete while iterating (not supported).
			toDelete = append(toDelete, currentState.EditSubGraph(subgraph))
		} else {
			toDescend = append(toDescend, currentState.EditSubGraph(subgraph))
		}
	}
	for _, subgraph := range toDelete {
		r.syncDeletedSubgraphs(subgraph, nil)
	}
	for _, subgraph := range toDescend {
		r.syncDeletedSubgraphs(subgraph, intendedState.SubGraph(subgraph.Name()))
	}
	if intendedState == nil && currentState.Items(true).Len() == 0 {
		if parent := currentState.EditParentGraph(); parent != nil {
			parent.DelSubGraph(currentState.Name())
			return true
		}
	}
	return false
}

// reconcileItems reconciles the state of items.
// Intended state can be nil, meaning that all items from the current state should be removed.
// Create/Modify/Delete operations are performed in two stages:
//  1. First all Delete + Modify operations are executed (incl. the first half of the Recreate).
//  2. Next all (Re)Create operations are carried out.
//
// In both cases, the items are traversed using DFS and the operations are executed
// in the forward or reverse topological order with respect to the dependencies.
// In the first stage, Delete/Modify operations are run in the DFS post-order, while
// in the seconds stage Create operations are lined up in the DFS pre-order.
// A simple stack structure is used to remember items which are being visited
// (recursion is intentionally avoided). In the first stage, each item is inserted into
// the stack only a constant number of times, whereas in the second stage an item
// could be added into the stack once for every outgoing edge to re-check dependencies
// of a missing (aka pending) item. Cumulatively, this gives us a time complexity O(V + E),
// where V represents the set of items and E the set of edges. In practise, the number of
// dependencies a configuration item will have is constant, hence the complexity can be
// simplified to just O(V).
// The sparsity of the graph is the reason why DFS was selected over BFS.
func (r *reconciler) reconcileItems(ctx context.Context, asyncManager *asyncManager,
	currentState dg.Graph, intendedState dg.GraphR, status *Status) error {
	graphName := currentState.Name()
	// currentState/intendedState could be just subgraphs.
	currentFullState := dg.GetGraphRoot(currentState)
	intendedFullState := dg.GetGraphRootR(intendedState)

	// Initialize stacks for both stages of DFS-based graph traversal.
	stage1Stack := newStack()
	stage2Stack := newStack()
	for _, itemRef := range currentState.DiffItems(intendedState) {
		stage1Stack.push(stackElem{itemRef: itemRef})
	}
	// Do not consider async ops that finalize *during* reconciliation as done.
	// Let them be processed in the next reconciliation run.
	// This prevents race-conditions and simplifies the reconciliation algorithm.
	asyncEndLimit := time.Now()
	for _, asyncOp := range asyncManager.listAllOps() {
		if _, _, _, found := r.getItem(currentState, asyncOp.params.itemRef); found {
			if asyncOp.status.done || asyncOp.status.cancelTimeout() {
				stage1Stack.push(stackElem{itemRef: asyncOp.params.itemRef})
			}
		}
	}
	// External items in the currentState might have changed. Traverse items that
	// depend on them to re-check dependencies.
	iter := currentState.Items(true)
	for iter.Next() {
		item, _ := iter.Item()
		itemRef := dg.Reference(item)
		if r.externalItem(currentFullState, intendedFullState, itemRef) {
			edgeIter := currentState.IncomingEdges(itemRef)
			for edgeIter.Next() {
				fromItem := edgeIter.Edge().FromItem
				stage1Stack.push(stackElem{itemRef: fromItem})
			}
		} else {
			edgeIter := currentState.OutgoingEdges(itemRef)
			for edgeIter.Next() {
				toItem := edgeIter.Edge().ToItem
				if r.externalItem(currentFullState, intendedFullState, toItem) {
					stage1Stack.push(stackElem{itemRef: itemRef})
				}
			}
		}
	}

	// Keep collecting a list of items which failed in this Reconciliation run
	// so that they are not touched again.
	failed := make(map[dg.ItemRef]struct{})

	// Stage 1: Run Delete + Modify operations
	// From every item to be deleted, run DFS and delete all items that depend on it
	// in the DFS *post-order*.
	// At this stage, an item state may change only in this direction:
	//     Created -> Deleting/Modifying -> Failure/<Deleted>
	// Only at the transition from Created we trigger DFS from an item.
	var (
		dfsRunning bool
		dfsOrigin  dg.ItemRef
		wait       bool
		globalErr  error
	)
	for !stage1Stack.isEmpty() {
		elem, _ := stage1Stack.pop()
		itemRef := elem.itemRef
		if r.externalItem(currentFullState, intendedFullState, itemRef) {
			// External items are not touched by the Reconciler.
			continue
		}
		if _, failed := failed[itemRef]; failed {
			continue
		}

		// Read the current and the intended item state and determine the next steps.
		var (
			// isOutside is true if item is outside of the graph selected
			// for reconciliation.
			// Note: with DFS traversal we can leave the boundary of the subgraph,
			// but we should not change any items (only make them pending if needed).
			isOutside, isInside bool
			explicitDel         bool
			newItem             dg.Item
			intendedPath        dg.SubGraphPath
		)
		// * the current state
		r.ensureStateData(currentFullState, itemRef)
		item, stateData, path, found := r.getItem(currentState, itemRef)
		if found {
			isInside = true
		} else {
			if item, stateData, path, found = r.getItem(currentFullState, itemRef); found {
				isOutside = true
				// Do not change items outside of the subgraph selected for Reconcile.
				newItem = item
			} else {
				// Create operation is called in the next stage.
				stage2Stack.push(stackElem{itemRef: itemRef})
				continue
			}
		}
		// * the intended state
		found = false
		if intendedState != nil {
			var intendedItem dg.Item
			intendedItem, _, intendedPath, found = r.getItem(intendedState, itemRef)
			if found {
				if isOutside {
					globalErr = fmt.Errorf("unable to update item %s: "+
						"item is outside of the subgraph selected for reconciliation",
						itemRef)
					continue
				}
				newItem = intendedItem
			}
		}
		if !found {
			explicitDel = isInside
		}

		// Clear context attributes used only for already DFS-traversed items.
		postOrder := elem.postOrder
		if postOrder {
			stateData.plannedOp = OperationUnknown
		}

		// Check if removal/modification of this item is blocked by another
		// asynchronous operation.
		if dfsRunning {
			if itemRef == dfsOrigin {
				dfsRunning = false
			}
			if wait {
				if itemRef == dfsOrigin {
					// do not carry over anymore
					wait = false
				}
				continue
			}
		}

		// Check if there is an asynchronous operation still running for this item.
		inProgress, asyncDeleted, err := r.checkAsyncOp(
			currentFullState, intendedFullState,
			itemRef, asyncManager, failed, stage2Stack, status, asyncEndLimit)
		if err != nil {
			globalErr = err
			continue
		}
		if inProgress {
			if dfsRunning {
				wait = true
			}
			continue
		}
		if asyncDeleted {
			// Item no longer exists, async Delete just completed.
			continue
		}
		// No continuous item states (*ing) below this point...

		// Prepare helper functions to avoid repetition.
		putItem := func() {
			if isOutside {
				dg.PutItemInto(currentFullState, item, stateData, path)
			} else {
				dg.PutItemInto(currentState, item, stateData, intendedPath)
			}
		}
		delItem := func() {
			if isOutside {
				dg.DelItemFrom(currentFullState, itemRef, path)
			} else {
				dg.DelItemFrom(currentState, itemRef, path)
			}
		}
		startDFS := func() {
			if !dfsRunning {
				dfsRunning = true
				dfsOrigin = itemRef
			}
		}

		// Handle explicit item removal.
		if explicitDel {
			if !r.itemIsCreated(stateData) {
				// Item is not created (due to an error), just remove item from the graph.
				delItem()
				continue
			}
			if postOrder {
				// ready for Delete (items depending on this were already traversed)
				if !r.wasAutoDeleted(currentFullState, intendedFullState, item) {
					opID, async, logEntry, err := r.runOperation(
						ctx, graphName, itemRef, item, nil,
						stateData.LastError, asyncManager)
					status.OperationLog = append(status.OperationLog, logEntry)
					if err != nil {
						stateData.LastOperation = OperationDelete
						stateData.LastError = err
						stateData.State = ItemStateFailure
						failed[itemRef] = struct{}{}
						putItem()
						if dfsRunning {
							wait = true
						}
						continue
					}
					if async {
						stateData.asyncOpID = opID
						stateData.State = ItemStateDeleting
						putItem()
						if dfsRunning {
							wait = true
						}
						continue
					}
				}
				delItem()
				continue
			}
			// Delete after all items that depends on it are removed first.
			stateData.plannedOp = OperationDelete
			stage1Stack.push(stackElem{itemRef: itemRef, postOrder: true})
			r.schedulePreDelOps(currentFullState, itemRef, stage1Stack)
			startDFS()
			continue
		}

		// Delete due to unsatisfied dependencies.
		if !r.hasSatisfiedDeps(currentFullState, newItem) {
			if !r.itemIsCreated(stateData) {
				delItem()
				continue
			}
			if postOrder {
				// ready for Delete (items depending on this were already traversed)
				if !r.wasAutoDeleted(currentFullState, intendedFullState, item) {
					opID, async, logEntry, err := r.runOperation(
						ctx, graphName, itemRef, item, nil,
						stateData.LastError, asyncManager)
					status.OperationLog = append(status.OperationLog, logEntry)
					if err != nil {
						stateData.LastOperation = OperationDelete
						stateData.LastError = err
						stateData.State = ItemStateFailure
						failed[itemRef] = struct{}{}
						putItem()
						if dfsRunning {
							wait = true
						}
						continue
					}
					if async {
						stateData.asyncOpID = opID
						stateData.State = ItemStateDeleting
						putItem()
						if dfsRunning {
							wait = true
						}
						continue
					}
				}
				delItem()
				continue
			}
			// Delete after all items that depends on it are removed first.
			stateData.plannedOp = OperationDelete
			stage1Stack.push(stackElem{itemRef: itemRef, postOrder: true})
			r.schedulePreDelOps(currentFullState, itemRef, stage1Stack)
			startDFS()
			continue
		}

		// Handle first half of the Recreate.
		if r.needToRecreate(currentFullState, item, newItem, stateData) {
			if postOrder {
				// ready for Delete (items depending on this were already traversed)
				opID, async, logEntry, err := r.runOperation(
					ctx, graphName, itemRef, item, nil,
					stateData.LastError, asyncManager)
				status.OperationLog = append(status.OperationLog, logEntry)
				if err != nil {
					stateData.LastOperation = OperationDelete
					stateData.LastError = err
					stateData.State = ItemStateFailure
					failed[itemRef] = struct{}{}
					putItem()
					if dfsRunning {
						wait = true
					}
					continue
				}
				if async {
					stateData.asyncOpID = opID
					stateData.State = ItemStateDeleting
					putItem()
					if dfsRunning {
						wait = true
					}
					continue
				}
				delItem()
				// Item is recreated in the second stage.
				stage2Stack.push(stackElem{itemRef: itemRef})
				continue
			}
			// Delete after all items that depends on it are removed first.
			stateData.plannedOp = OperationDelete
			stage1Stack.push(stackElem{itemRef: itemRef, postOrder: true})
			r.schedulePreDelOps(currentFullState, itemRef, stage1Stack)
			startDFS()
			continue
		}

		// Item can be Created/Modified below this point...
		if isOutside || r.putOpIsBlocked(currentFullState, newItem, failed) {
			continue
		}

		// Create operation is called in the next stage.
		if !r.itemIsCreated(stateData) {
			stage2Stack.push(stackElem{itemRef: itemRef})
			continue
		}

		// Handle item modification.
		if !item.Equal(newItem) {
			if postOrder {
				opID, async, logEntry, err := r.runOperation(
					ctx, graphName, itemRef, item, newItem,
					stateData.LastError, asyncManager)
				status.OperationLog = append(status.OperationLog, logEntry)
				if err != nil {
					stateData.LastOperation = OperationModify
					stateData.LastError = err
					stateData.State = ItemStateFailure
					stateData.newItem = nil
					failed[itemRef] = struct{}{}
					putItem()
					if dfsRunning {
						wait = true
					}
					continue
				}
				if async {
					stateData.asyncOpID = opID
					stateData.State = ItemStateModifying
					putItem()
					if dfsRunning {
						wait = true
					}
					continue
				}
				item = newItem
				stateData.LastOperation = OperationModify
				stateData.LastError = nil
				stateData.State = ItemStateCreated
				stateData.modified = true
				stateData.newItem = nil
				putItem()
				// Some pending items might be now ready to be created.
				stage2Stack.push(stackElem{itemRef: itemRef})
				continue
			}
			stateData.plannedOp = OperationModify
			stateData.newItem = newItem
			stage1Stack.push(stackElem{itemRef: itemRef, postOrder: true})
			r.schedulePreModifyOps(currentFullState, itemRef, stage1Stack)
			startDFS()
			continue
		}

		// Just update the item path if needed.
		if path.Compare(intendedPath) != 0 {
			putItem()
		}
	}

	// Stage 2: Run (Re)Create operations
	// From every item to be created or that has been modified, run DFS and maybe
	// create some pending items (present in intended, missing in current) that depend
	// on it in the DFS *pre-order*.
	// At this stage, an item state may change only in this direction:
	//     <Pending> -> Created/Failure
	for !stage2Stack.isEmpty() {
		elem, _ := stage2Stack.pop()
		itemRef := elem.itemRef
		if r.externalItem(currentFullState, intendedFullState, itemRef) {
			// External items are not touched by the Reconciler.
			continue
		}
		if _, failed := failed[itemRef]; failed {
			continue
		}

		// Read intended item value and current state data.
		r.ensureStateData(currentFullState, itemRef)
		_, stateData, _, found := r.getItem(currentFullState, itemRef)
		if !found {
			stateData = &ItemStateData{}
		}
		item, _, path, found := r.getItem(intendedFullState, itemRef)
		if !found {
			// Removed in the previous stage.
			// XXX We could improve stage1 to avoid spurious inserts into stage2Stack.
			continue
		}

		if stateData.State.Continuous() {
			// Async operations are checked for completion only in the first stage.
			continue
		}
		modified := stateData.modified
		stateData.modified = false

		// Handle (Re)Create.
		putItem := func() {
			dg.PutItemInto(currentFullState, item, stateData, path)
		}
		if !r.itemIsCreated(stateData) {
			if !r.hasSatisfiedDeps(currentFullState, item) ||
				r.putOpIsBlocked(currentFullState, item, failed) {
				continue
			}
			opID, async, logEntry, err := r.runOperation(
				ctx, graphName, itemRef, nil, item,
				stateData.LastError, asyncManager)
			status.OperationLog = append(status.OperationLog, logEntry)
			if err != nil {
				stateData.LastOperation = OperationCreate
				stateData.LastError = err
				stateData.State = ItemStateFailure
				failed[itemRef] = struct{}{}
				putItem()
				continue
			}
			if async {
				stateData.asyncOpID = opID
				stateData.State = ItemStateCreating
				putItem()
				continue
			}
			stateData.LastOperation = OperationCreate
			stateData.LastError = nil
			stateData.State = ItemStateCreated
			putItem()
			r.schedulePostPutOps(currentFullState, intendedFullState, itemRef, stage2Stack)
			continue
		}

		// Schedule possible Create operations that follow from a Modify.
		if modified {
			r.schedulePostPutOps(currentFullState, intendedFullState, itemRef, stage2Stack)
		}
	}

	// Mark modified external items as processed.
	iter = currentState.Items(true)
	for iter.Next() {
		item, state := iter.Item()
		itemRef := dg.Reference(item)
		if r.externalItem(currentFullState, intendedFullState, itemRef) {
			if stateData, ok := state.(*ItemStateData); ok {
				stateData.ExternallyModified = false
			}
		}
	}
	return globalErr
}

// Run Create, Delete or Modify. Which operation to run exactly is determined
// based on nil/non-nil values of prevItem & newItem. Operation may continue
// in background. Remember to check Configurator.NeedsRecreate() before running
// modification.
func (r *reconciler) runOperation(ctx context.Context, graphName string,
	itemRef dg.ItemRef, prevItem, newItem dg.Item, prevErr error,
	asyncManager *asyncManager) (
	opID uint64, async bool, logEntry OpLogEntry, err error) {

	// Prepare operation to execute.
	var configurator Configurator
	var execOperation func(ctx context.Context) error
	if newItem != nil {
		logEntry.Item = newItem
		configurator = r.CR.GetConfigurator(newItem)
		if configurator == nil {
			err = errMissingConfigurator(newItem)
		}
		if prevItem != nil {
			logEntry.Operation = OperationModify
			execOperation = func(ctx context.Context) error {
				if IsMockRun(ctx) {
					return nil
				}
				return configurator.Modify(ctx, prevItem, newItem)
			}
		} else {
			logEntry.Operation = OperationCreate
			execOperation = func(ctx context.Context) error {
				if IsMockRun(ctx) {
					return nil
				}
				return configurator.Create(ctx, newItem)
			}
		}
	} else {
		logEntry.Item = prevItem
		logEntry.Operation = OperationDelete
		configurator = r.CR.GetConfigurator(prevItem)
		if configurator == nil {
			err = errMissingConfigurator(prevItem)
		}
		execOperation = func(ctx context.Context) error {
			if IsMockRun(ctx) {
				return nil
			}
			return configurator.Delete(ctx, prevItem)
		}
	}

	// Prepare context that will allow the operation:
	//  - to continue in background
	//  - to be canceled
	startTime := time.Now()
	if err == nil {
		opID = rand.Uint64()
		opCtx := &opCtx{
			opID:         opID,
			graphName:    graphName,
			asyncManager: asyncManager,
		}
		ctx = newOpCtx(ctx, opCtx)
		ctx, cancel := context.WithCancel(ctx)
		err = execOperation(ctx)
		if opCtx.runAsync {
			// asynchronous execution
			logEntry.StartTime = startTime
			logEntry.InProgress = true
			asyncManager.addAsyncOp(asyncOpParams{
				opID:      opCtx.opID,
				startTime: logEntry.StartTime,
				itemRef:   itemRef,
				graphName: graphName,
				cancel:    cancel,
			})
			return opID, true, logEntry, nil
		} else {
			// Do not leak cancel context.
			cancel()
		}
	}

	// synchronous execution
	logEntry.Err = err
	logEntry.PrevErr = prevErr
	logEntry.StartTime = startTime
	logEntry.EndTime = time.Now()
	return opID, false, logEntry, err
}

// checkAsyncOp checks if there is an asynchronous operation running for a given item.
// Function can also post-process and log completed async operation.
func (r *reconciler) checkAsyncOp(currentFullState dg.Graph, intendedFullState dg.GraphR,
	itemRef dg.ItemRef, asyncManager *asyncManager, failed map[dg.ItemRef]struct{},
	stage2Stack *stack, status *Status, endLimit time.Time) (
	asyncInProgress, deleted bool, err error) {

	// Check if async operation is/was running.
	item, stateData, path, found := r.getItem(currentFullState, itemRef)
	if !found {
		return false, false, nil
	}
	if !stateData.State.Continuous() {
		return false, false, nil
	}
	opID := stateData.asyncOpID
	asyncOp, found := asyncManager.getAsyncOp(opID)
	if !found {
		return true, false, fmt.Errorf("missing async operation: %d", opID)
	}
	if !asyncOp.status.done && !asyncOp.status.cancelTimeout() {
		// still running
		return true, false, nil
	}
	if asyncOp.status.endTime.After(endLimit) {
		// Finalized during reconciliation.
		// Process it in the next reconciliation run instead to avoid race conditions.
		return true, false, nil
	}

	// Async operation has finalized.
	opErr := asyncOp.status.err
	if asyncOp.status.cancelTimeout() {
		opErr = errors.New("failed to react to cancel() in time")
	}
	operation := stateData.State.ContinuousToOperation()
	logEntry := OpLogEntry{
		Item:       item,
		Operation:  operation,
		StartTime:  asyncOp.params.startTime,
		EndTime:    asyncOp.status.endTime,
		CancelTime: asyncOp.status.cancelTime,
		InProgress: false,
		Err:        opErr,
		PrevErr:    stateData.LastError,
	}
	status.OperationLog = append(status.OperationLog, logEntry)
	// remove context for the async operation
	asyncManager.delAsyncOp(opID)

	// Update item state.
	var delItem, postPut bool
	stateData.LastError = opErr
	stateData.LastOperation = operation
	if opErr != nil {
		stateData.State = ItemStateFailure
		failed[itemRef] = struct{}{}
		stateData.newItem = nil
	} else {
		switch operation {
		case OperationDelete:
			delItem = true
		case OperationModify:
			stateData.State = ItemStateCreated
			item = stateData.newItem
			stateData.newItem = nil
			postPut = true
		case OperationCreate:
			stateData.State = ItemStateCreated
			postPut = true
		}
	}
	if delItem {
		dg.DelItemFrom(currentFullState, itemRef, path)
	} else {
		dg.PutItemInto(currentFullState, item, stateData, path)
	}
	if postPut {
		r.schedulePostPutOps(
			currentFullState, intendedFullState, itemRef, stage2Stack)
	}
	return false, delItem, nil
}

// If changingItem is about to be deleted, iterate over items that depend on it
// and check if they need to be deleted first because their dependencies will no
// longer be satisfied.
func (r *reconciler) schedulePreDelOps(
	currentFullState dg.GraphR, changingItem dg.ItemRef, stack *stack) {
	iter := currentFullState.IncomingEdges(changingItem)
	for iter.Next() {
		edge := iter.Edge()
		_, stateData, _, _ := r.getItem(currentFullState, edge.FromItem)
		if stateData.State.Continuous() {
			// Check if delete should wait for an async operation.
			stack.push(stackElem{itemRef: edge.FromItem})
			continue
		}
		if r.itemIsCreated(stateData) {
			// Removal of changingItem breaks dependencies.
			stack.push(stackElem{itemRef: edge.FromItem})
		}
	}
}

// If changingItem is about to be modified, iterate over items that depend on it
// and check if they need to be deleted first because their dependencies will no
// longer be satisfied.
func (r *reconciler) schedulePreModifyOps(
	currentFullState dg.GraphR, changingItem dg.ItemRef, stack *stack) {
	_, stateData, _, _ := r.getItem(currentFullState, changingItem)
	newItem := stateData.newItem
	iter := currentFullState.IncomingEdges(changingItem)
	for iter.Next() {
		edge := iter.Edge()
		dep := edge.Dependency
		_, stateData, _, _ = r.getItem(currentFullState, edge.FromItem)
		if stateData.State.Continuous() {
			// Check if modification should wait for an async operation.
			stack.push(stackElem{itemRef: edge.FromItem})
			continue
		}
		if r.itemIsCreated(stateData) {
			if dep.MustSatisfy != nil && !dep.MustSatisfy(newItem) {
				// Modification of changingItem breaks dependencies.
				stack.push(stackElem{itemRef: edge.FromItem})
				continue
			}
			if dep.Attributes.RecreateWhenModified {
				stack.push(stackElem{itemRef: edge.FromItem})
				continue
			}
		}
	}
}

// Schedule pending items (present in the intended state, missing in the current state),
// to be (re)processed after one of their dependencies was (Re)Created or Modified.
func (r *reconciler) schedulePostPutOps(
	currentFullState, intendedFullState dg.GraphR, itemRef dg.ItemRef, stack *stack) {
	iter := intendedFullState.IncomingEdges(itemRef)
	for iter.Next() {
		edge := iter.Edge()
		if _, _, _, found := r.getItem(currentFullState, edge.FromItem); !found {
			stack.push(stackElem{itemRef: edge.FromItem})
		}
	}
}

func (r *reconciler) itemIsCreated(itemState *ItemStateData) bool {
	return itemState.State == ItemStateCreated ||
		itemState.State == ItemStateModifying ||
		(itemState.State == ItemStateFailure &&
			itemState.LastOperation != OperationCreate)
}

func (r *reconciler) externalItem(currentFullState, intendedFullState dg.GraphR,
	itemRef dg.ItemRef) bool {
	if item, _, _, exists := currentFullState.Item(itemRef); exists {
		return item.External()
	}
	if item, _, _, exists := intendedFullState.Item(itemRef); exists {
		return item.External()
	}
	return false
}

func (r *reconciler) hasSatisfiedDeps(currentFullState dg.GraphR, item dg.Item) bool {
	for _, dep := range item.Dependencies() {
		if !r.satisfiedDep(currentFullState, dep) {
			return false
		}
	}
	return true
}

func (r *reconciler) satisfiedDep(currentFullState dg.GraphR, dep dg.Dependency) bool {
	depItem, depState, _, exists := r.getItem(currentFullState, dep.RequiredItem)
	if !exists {
		return false
	}
	if !r.itemIsCreated(depState) {
		return false
	}
	if depState.plannedOp == OperationDelete {
		return false
	}
	if dep.MustSatisfy != nil {
		if !dep.MustSatisfy(depItem) {
			return false
		}
		if depState.State == ItemStateModifying ||
			depState.plannedOp == OperationModify {
			if !dep.MustSatisfy(depState.newItem) {
				return false
			}
		}
	}
	return true
}

func (r *reconciler) wasAutoDeleted(currentFullState, intendedFullState dg.GraphR,
	item dg.Item) bool {
	for _, dep := range item.Dependencies() {
		if !dep.Attributes.AutoDeletedByExternal {
			continue
		}
		if r.externalItem(currentFullState, intendedFullState, dep.RequiredItem) &&
			!r.satisfiedDep(currentFullState, dep) {
			return true
		}
	}
	return false
}

// Do not create or modify an item if at least one of its dependencies has failed
// during this reconciliation or has an async operation ongoing.
func (r *reconciler) putOpIsBlocked(currentFullState dg.GraphR, item dg.Item,
	failed map[dg.ItemRef]struct{}) bool {
	for _, dep := range item.Dependencies() {
		if _, failed := failed[dep.RequiredItem]; failed {
			return true
		}
		_, depState, _, exists := r.getItem(currentFullState, dep.RequiredItem)
		if exists && depState.State == ItemStateModifying {
			return true
		}
	}
	return false
}

func (r *reconciler) needToRecreate(currentFullState dg.GraphR, item, newItem dg.Item,
	itemState *ItemStateData) bool {
	if !r.itemIsCreated(itemState) {
		return false
	}
	iter := currentFullState.OutgoingEdges(dg.Reference(item))
	for iter.Next() {
		edge := iter.Edge()
		if !edge.Dependency.Attributes.RecreateWhenModified {
			continue
		}
		if depItem, depState, _, exists := r.getItem(currentFullState, edge.ToItem); exists {
			if depState.plannedOp == OperationModify {
				return true
			}
			if depItem.External() && depState.ExternallyModified {
				return true
			}
		}
	}
	if !item.Equal(newItem) {
		configurator := r.CR.GetConfigurator(newItem)
		if configurator != nil {
			return configurator.NeedsRecreate(item, newItem)
		}
	}
	return false
}

func (r *reconciler) getItem(graph dg.GraphR, itemRef dg.ItemRef) (
	item dg.Item, stateData *ItemStateData, path dg.SubGraphPath, exists bool) {
	var state dg.ItemState
	item, state, path, exists = graph.Item(itemRef)
	if !exists {
		return
	}
	var ok bool
	if stateData, ok = state.(*ItemStateData); !ok {
		stateData = r.defaultItemState()
	}
	return
}

func (r *reconciler) ensureStateData(graph dg.Graph, itemRef dg.ItemRef) {
	item, state, _, exists := graph.Item(itemRef)
	if exists {
		if _, ok := state.(*ItemStateData); !ok {
			stateData := r.defaultItemState()
			graph.PutItem(item, stateData)
		}
	}
}

// Default state to assume if missing in the current state graph.
// This may be used if the user added/updated items inside the graph
// but forgot to supply state data.
func (r *reconciler) defaultItemState() *ItemStateData {
	return &ItemStateData{
		State:         ItemStateCreated,
		LastOperation: OperationCreate,
	}
}
