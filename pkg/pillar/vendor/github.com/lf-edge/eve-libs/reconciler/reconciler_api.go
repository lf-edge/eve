// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"context"
	"fmt"
	"strings"
	"time"

	dg "github.com/lf-edge/eve-libs/depgraph"
)

// Reconciler implements state reconciliation using two dependency graphs,
// one modeling the current state and the other the intended state.
// For more information, please refer to README.md.
type Reconciler interface {
	// Reconcile : run state reconciliation. The function makes state transitions
	// (using Configurators) to get from the currentState (closer) to the intended
	// state. The function updates the currentState graph to reflect all the performed
	// changes.
	// Some state transitions may continue running asynchronously in the background,
	// see comments for the returned Status, and refer to README.md for even more detailed
	// documentation.
	Reconcile(ctx context.Context,
		currentState dg.Graph, intendedState dg.GraphR) Status
}

// New creates a new Reconciler.
// Note that reconciler is a stateless object and so there is no need to keep it
// after Reconcile() returns. Even if there are some async operations running
// in the background, you can resume the reconciliation with a new instance
// of Reconciler, just keep the graph with the current state (do not rebuild
// from scratch).
func New(cr ConfiguratorRegistry) Reconciler {
	return &reconciler{CR: cr}
}

// Configurator implements Create, Modify and Delete operations for items of the same type.
// For Reconciler it is a "backend" which it calls as needed to sync the actual and
// the intended state.
type Configurator interface {
	// Create should create the item (e.g. create a Linux bridge with the given parameters).
	Create(ctx context.Context, item dg.Item) error
	// Modify should change the item to the new desired state (e.g. change interface IP address).
	Modify(ctx context.Context, oldItem, newItem dg.Item) (err error)
	// Delete should remove the item (e.g. stop process).
	Delete(ctx context.Context, item dg.Item) error
	// NeedsRecreate should return true if changing the item to the new desired state
	// requires the item to be completely re-created. Reconciler will then perform the change
	// as Delete(oldItem) followed by Create(newItem) instead of calling Modify.
	NeedsRecreate(oldItem, newItem dg.Item) (recreate bool)
}

// ContinueInBackground allows to run Create/Modify/Delete asynchronously.
// If changing the state of an item requires to perform a long-running task,
// such as downloading a large file from the Internet, it is recommended
// to continue this work in the background in a separate Go routine, in order
// to not block other *independent* state transitions.
// Note that Reconciler ensures that two items might change their state in parallel
// only if there are no dependencies between them, either direct or transitive.
// And if there are any restrictions for parallel execution besides item dependencies,
// synchronization primitives like mutexes are always an option.
//
// Example Usage:
//
//	func (c *MyConfigurator) Create(ctx context.Context, item depgraph.Item) error {
//	    done := reconciler.ContinueInBackground(ctx)
//	    go func() {
//	        // Remember to stop if ctx.Done() fires (return error if failed to complete)
//	        err := longRunningTask(ctx)
//	        done(err)
//	     }
//	     // exit immediately with nil error
//	     return nil
//	}
func ContinueInBackground(ctx context.Context) (done func(error)) {
	opCtx := getOpCtx(ctx)
	opCtx.runAsync = true
	return func(err error) {
		opCtx.asyncManager.opIsDone(opCtx.opID, opCtx.graphName, err)
	}
}

// MockRun : Use this method to create context for "mock" Reconcile().
// When used, reconciler will proceed with the reconciliation algorithm as normally
// except that it will not actually call any Create/Delete/Modify operations
// provided by Configurators. Instead, it will pretend that all scheduled operations
// were run and all returned nil errors. This is useful for unit testing, because it
// allows to compare the sequence of executed config operations against the expectation
// without actually running those operations and interfering with the host system.
func MockRun(ctx context.Context) context.Context {
	return context.WithValue(ctx, mockRunCtxKey, &mockRunAttrs{})
}

// IsMockRun : Is this context configured for mock reconciliation?
func IsMockRun(ctx context.Context) bool {
	_, isMockRun := ctx.Value(mockRunCtxKey).(*mockRunAttrs)
	return isMockRun
}

// ConfiguratorRegistry implements mapping between items and configurators that manage
// their state transitions.
type ConfiguratorRegistry interface {
	// GetConfigurator returns configurator registered for the given item.
	// Returns nil if there is no configurator registered.
	GetConfigurator(item dg.Item) Configurator
}

// Status of a state reconciliation as returned by Reconcile().
type Status struct {
	// Err : non-nil if any state transition failed.
	Err error
	// NewCurrentState : updated graph with the current state.
	// If current state was passed as nil, this contains a newly created graph.
	NewCurrentState dg.Graph
	// OperationLog : log of all executed operations.
	OperationLog OperationLog
	// AsyncOpsInProgress : true if any state transition still continues running
	// asynchronously. When at least one of the asynchronous operations finalizes,
	// the returned channel ReadyToResume will fire.
	AsyncOpsInProgress bool
	// ReadyToResume : Fires when at least one of the asynchronous operations from
	// a previous reconciliation finalizes. Use this channel only until the next
	// reconciliation (even if the next reconciliation is for a different subgraph),
	// then replace it with the newly returned Status.ReadyToResume.
	// Returns name of the (sub)graph ready to continue reconciling.
	// This may be useful if you do selective reconciliations with subgraphs.
	ReadyToResume <-chan string
	// CancelAsyncOps : send cancel signal to either all asynchronously running operations,
	// or only to those running for items matched by the provided callback.
	// They will receive the signal through ctx.Done() and should respect it.
	CancelAsyncOps CancelFunc
	// WaitForAsyncOps : wait for all asynchronously running operations to complete.
	// Beware that this may block endlessly if at least one of the operations
	// keeps ignoring ctx.Done().
	// Note that this function waits for all currently running asynchronous operations.
	// Waiting for only a subset of operations is not yet supported.
	WaitForAsyncOps func()
}

// CancelFunc is used to cancel all or only some asynchronously running operations.
type CancelFunc func(cancelForItem func(ref dg.ItemRef) bool)

// OperationLog : log of all operations executed during a single Reconcile().
// Operations are ordered by StartTime.
type OperationLog []OpLogEntry

// OpLogEntry : log entry for a single operation executed during Reconcile().
// InProgress is returned as true and EndTime as zero value if the operation
// continues running asynchronously.
type OpLogEntry struct {
	Item       dg.Item
	Operation  Operation
	StartTime  time.Time
	EndTime    time.Time
	CancelTime time.Time
	InProgress bool
	Err        error
	// PrevErr : error (or nil) from the previous state transition for this item.
	PrevErr error
}

// String : a multi-line description of all executed operations during a single Reconcile().
func (l OperationLog) String() string {
	var ops []string
	for _, op := range l {
		var inProgress string
		if op.InProgress {
			inProgress = " (in-progress)"
		}
		var withError string
		if op.Err != nil {
			withError = " with error " + op.Err.Error()
		}
		ops = append(ops, fmt.Sprintf("[%v - %v]%s %s item type:%s name:%s%s",
			op.StartTime, op.EndTime, inProgress, strings.Title(op.Operation.String()),
			op.Item.Type(), op.Item.Name(), withError))
	}
	return strings.Join(ops, "\n")
}

// ItemStateData encapsulates state data for a single item instance.
// Implements depgraph.ItemState.
// In the graph with the intended state this is not expected to be used, instead
// leave state of every item as nil.
// When building/updating the graph with the current state, do not forget to put
// an instance of *ItemStateData next to each item and set the exported fields
// (.State, .LastOperation, .LastError) appropriately, so that the Reconciler
// works with a correct representation of the current state.
type ItemStateData struct {
	// State : state of the item.
	State ItemState
	// LastOperation : last operation executed for this item.
	LastOperation Operation
	// LastError : error (or nil) returned by the last operation executed for this item.
	LastError error

	// ExternallyModified: this should be set by the user whenever the associated external
	// item has been just modified (ignored for non-external items). This is needed for
	// the Reconciler to know when to recreate items that depend on it and require re-creation
	// (RecreateWhenModified==true).
	// After this has been processed, the Reconciler sets it back to false (to not react
	// to the same modification multiple times).
	// XXX Try to find a better solution to this problem.
	ExternallyModified bool

	// Attributes below are for internal-use only:

	// ID of the current/last asynchronous operation run for the item .
	asyncOpID uint64
	// Operation currently planned inside Reconcile().
	plannedOp Operation
	// Used when plannedOp is OperationModify or State is ItemStateModifying.
	newItem dg.Item
	// Used during Reconcile() to mark items that were modified.
	// Cleared by stage2 of Reconcile().
	modified bool
}

// String returns description of an item state.
func (d *ItemStateData) String() string {
	return fmt.Sprintf("state: %v; last operation: %v; last error: %v",
		d.State, d.LastOperation, d.LastError)
}

// IsCreated : true if Reconciler has created the item.
func (d *ItemStateData) IsCreated() bool {
	return d.State == ItemStateCreated ||
		d.State == ItemStateModifying ||
		(d.State == ItemStateFailure &&
			(d.LastOperation == OperationDelete || d.LastOperation == OperationModify))
}

// WithError : returns non-nil error if the last operation executed
// for this item failed.
func (d *ItemStateData) WithError() error {
	if d.State == ItemStateFailure {
		return d.LastError
	}
	return nil
}

// InTransition returns true if the item state is being changed asynchronously.
func (d *ItemStateData) InTransition() bool {
	return d.State.Continuous()
}

// ItemState : state of an item.
type ItemState int

const (
	// ItemStateUnknown : item state is not known.
	ItemStateUnknown ItemState = iota
	// ItemStateCreated : item is successfully created.
	ItemStateCreated
	// ItemStateFailure : last Create/Modify/Delete operation failed.
	// Expect to find non-nil ItemStateData.LastError.
	ItemStateFailure
	// ItemStateCreating : item is being asynchronously created.
	ItemStateCreating
	// ItemStateDeleting : item is being asynchronously removed.
	ItemStateDeleting
	// ItemStateModifying : item is being asynchronously modified.
	ItemStateModifying
)

// String returns string representation of the item state.
func (s ItemState) String() string {
	switch s {
	case ItemStateUnknown:
		return "unknown"
	case ItemStateCreated:
		return "created"
	case ItemStateFailure:
		return "failure"
	case ItemStateCreating:
		return "creating"
	case ItemStateDeleting:
		return "deleting"
	case ItemStateModifying:
		return "modifying"
	}
	return ""
}

// Continuous returns true if the state represents a continuous action.
func (s ItemState) Continuous() bool {
	switch s {
	case ItemStateCreating:
		return true
	case ItemStateDeleting:
		return true
	case ItemStateModifying:
		return true
	}
	return false
}

// ContinuousToOperation converts continuous state to the corresponding
// operation.
func (s ItemState) ContinuousToOperation() Operation {
	switch s {
	case ItemStateCreating:
		return OperationCreate
	case ItemStateDeleting:
		return OperationDelete
	case ItemStateModifying:
		return OperationModify
	}
	return OperationUnknown
}

// Operation : operation done over an item.
type Operation int

const (
	// OperationUnknown : unknown operation
	OperationUnknown Operation = iota
	// OperationCreate : Create() operation
	OperationCreate
	// OperationDelete : Delete() operation
	OperationDelete
	// OperationModify : Modify() operation
	OperationModify
)

// String returns string representation of the operation.
func (o Operation) String() string {
	switch o {
	case OperationUnknown:
		return "unknown"
	case OperationCreate:
		return "create"
	case OperationDelete:
		return "delete"
	case OperationModify:
		return "modify"
	}
	return ""
}

// ToContinousState converts operation to the corresponding continuous item state.
func (o Operation) ToContinousState() ItemState {
	switch o {
	case OperationCreate:
		return ItemStateCreating
	case OperationDelete:
		return ItemStateDeleting
	case OperationModify:
		return ItemStateModifying
	}
	return ItemStateUnknown
}
