// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"fmt"
	"reflect"

	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"

	rec "github.com/lf-edge/eve/libs/reconciler"
)

// BeMockItem checks if expectation matches the given mock Item.
func BeMockItem(item mockItem) types.GomegaMatcher {
	return &mockItemMatcher{expItem: item}
}

// OperationMatcher : matcher for synchronous operation
type OperationMatcher interface {
	types.GomegaMatcher
	WithError(errMsg string) types.GomegaMatcher
	WithPrevError(errMsg string) types.GomegaMatcher
	WithoutPrevError() types.GomegaMatcher
	Before(item mockItem) RefOperationMatcherWithAsync
	After(item mockItem) RefOperationMatcher
}

// AsyncOperationMatcher : matcher for asynchronous operation
type AsyncOperationMatcher interface {
	types.GomegaMatcher
	After(item mockItem) RefOperationMatcher
}

// RefOperationMatcher : reference another synchronous operation and check
// the relative ordering.
type RefOperationMatcher interface {
	types.GomegaMatcher
	IsCreated() types.GomegaMatcher
	IsDeleted() types.GomegaMatcher
	IsModified() types.GomegaMatcher
	IsRecreated() types.GomegaMatcher
}

// RefOperationMatcher : reference another operation and check the relative ordering.
type RefOperationMatcherWithAsync interface {
	RefOperationMatcher
	IsBeingCreated() types.GomegaMatcher
	IsBeingDeleted() types.GomegaMatcher
	IsBeingModified() types.GomegaMatcher
	IsBeingRecreated() types.GomegaMatcher
}

func BeCreated() OperationMatcher {
	return &opMatcher{
		expOp: operationCreate,
	}
}

func BeDeleted() OperationMatcher {
	return &opMatcher{
		expOp: operationDelete,
	}
}

func BeModified() OperationMatcher {
	return &opMatcher{
		expOp: operationModify,
	}
}

func BeRecreated() OperationMatcher {
	return &opMatcher{
		expOp: operationReCreate,
	}
}

func BeingCreated() AsyncOperationMatcher {
	return &opMatcher{
		expOp:         operationCreate,
		expInProgress: true,
	}
}

func BeingDeleted() AsyncOperationMatcher {
	return &opMatcher{
		expOp:         operationDelete,
		expInProgress: true,
	}
}

func BeingModified() AsyncOperationMatcher {
	return &opMatcher{
		expOp:         operationModify,
		expInProgress: true,
	}
}

func BeingRecreated() AsyncOperationMatcher {
	return &opMatcher{
		expOp:         operationReCreate,
		expInProgress: true,
	}
}

// mockItemMatcher implements types.GomegaMatcher.
type mockItemMatcher struct {
	expItem mockItem
}

func (m *mockItemMatcher) Match(actual interface{}) (success bool, err error) {
	item, ok := actual.(mockItem)
	if !ok {
		return false, fmt.Errorf("mockItemMatcher expects a mock Item")
	}
	return item.itemType == m.expItem.itemType &&
			item.name == m.expItem.name &&
			item.isExternal == m.expItem.isExternal &&
			reflect.DeepEqual(item.staticAttrs, m.expItem.staticAttrs) &&
			reflect.DeepEqual(item.modifiableAttrs, m.expItem.modifiableAttrs),
		nil
}

func (m *mockItemMatcher) FailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected\n%s\nto be mock item\n%s",
		format.Object(actual, 1),
		format.Object(m.expItem, 1))
}

func (m *mockItemMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected\n%s\nto NOT be mock item\n%s",
		format.Object(actual, 1),
		format.Object(m.expItem, 1))
}

// opMatcher implements OperationMatcher
type opMatcher struct {
	expOp         operation
	expBefore     *expectedOp
	expAfter      *expectedOp
	expError      string
	checkPrevErr  bool
	expPrevError  string
	expInProgress bool
}

type expectedOp struct {
	item       mockItem
	op         operation
	inProgress bool
}

// operation : just like Operation enum but additionally with ReCreate.
type operation int

const (
	operationUnknown operation = iota
	operationCreate
	operationDelete
	operationModify
	operationReCreate
)

func (m *opMatcher) Match(actual interface{}) (success bool, err error) {
	item, ok := actual.(mockItem)
	if !ok {
		return false, fmt.Errorf("OperationMatcher expects a mock Item")
	}
	opLog := m.findOp(item, m.expOp)
	if opLog == nil {
		return false, nil
	}
	if m.expInProgress && !opLog.InProgress {
		return false, nil
	}
	var opErr, prevOpErr string
	if opLog.Err != nil {
		opErr = opLog.Err.Error()
	}
	if opLog.PrevErr != nil {
		prevOpErr = opLog.PrevErr.Error()
	}
	if m.expError != opErr {
		return false, nil
	}
	if m.checkPrevErr && m.expPrevError != prevOpErr {
		return false, nil
	}
	if m.expBefore != nil {
		opLog2 := m.findOp(m.expBefore.item, m.expBefore.op)
		if opLog2 == nil {
			return false, nil
		}
		if m.expBefore.inProgress && !opLog2.InProgress {
			return false, nil
		}
		if opLog.EndTime.After(opLog2.StartTime) {
			return false, nil
		}
	}
	if m.expAfter != nil {
		opLog2 := m.findOp(m.expAfter.item, m.expAfter.op)
		if opLog2 == nil {
			return false, nil
		}
		if opLog2.EndTime.After(opLog.StartTime) {
			return false, nil
		}
	}
	return true, nil
}

func (m *opMatcher) findOp(item mockItem, op operation) *rec.OpLogEntry {
	if op == operationUnknown {
		panic("unreachable")
	}
	var deleted bool
	for _, logEntry := range status.OperationLog {
		if logEntry.Item.Name() != item.Name() {
			continue
		}
		if int(op) == int(logEntry.Operation) ||
			(op == operationReCreate &&
				deleted && logEntry.Operation == rec.OperationCreate) {
			return &logEntry
		}
		deleted = logEntry.Operation == rec.OperationDelete
	}
	return nil
}

func expOpToString(expOp operation) string {
	switch expOp {
	case operationCreate:
		return "created"
	case operationDelete:
		return "deleted"
	case operationModify:
		return "modified"
	case operationReCreate:
		return "recreated"
	}
	return "<unknown>"
}

func (m *opMatcher) failureMessage(actual interface{}, negated bool) (message string) {
	var expVerb, expOp, expErr, expPrevErr, expOrder string
	if m.expInProgress {
		expVerb = "being"
	} else {
		expVerb = "to be"
	}
	if negated {
		expVerb = "NOT " + expVerb
	}
	expOp = expOpToString(m.expOp)
	expErr = "successfully"
	if m.expError != "" {
		expErr = fmt.Sprintf("with error %s", m.expError)
	}
	if m.checkPrevErr {
		if m.expPrevError == "" {
			expPrevErr = " without previous error"
		} else {
			expPrevErr = fmt.Sprintf(" with previous error %s", m.expPrevError)
		}
	}
	if m.expBefore != nil {
		being := "being "
		if !m.expBefore.inProgress {
			being = ""
		}
		expOrder = fmt.Sprintf("before item\n%s is %s%s",
			format.Object(m.expBefore.item, 1),
			being, expOpToString(m.expBefore.op))
	}
	if m.expAfter != nil {
		expOrder = fmt.Sprintf("after item\n%s is %s",
			format.Object(m.expAfter.item, 1),
			expOpToString(m.expAfter.op))
	}
	actualOps := fmt.Sprintf("Executed operations:\n%v", status.OperationLog)
	return fmt.Sprintf("Expected\n%s\n%s %s %s%s %s\n%s",
		format.Object(actual, 1), expVerb, expOp, expErr, expPrevErr,
		expOrder, actualOps)
}

func (m *opMatcher) FailureMessage(actual interface{}) (message string) {
	return m.failureMessage(actual, false)
}

func (m *opMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return m.failureMessage(actual, true)
}

func (m *opMatcher) WithError(errMsg string) types.GomegaMatcher {
	m.expError = errMsg
	return m
}

func (m *opMatcher) WithPrevError(errMsg string) types.GomegaMatcher {
	m.expPrevError = errMsg
	m.checkPrevErr = true
	return m
}

func (m *opMatcher) WithoutPrevError() types.GomegaMatcher {
	m.expPrevError = ""
	m.checkPrevErr = true
	return m
}

func (m *opMatcher) Before(item mockItem) RefOperationMatcherWithAsync {
	m.expBefore = &expectedOp{
		item: item,
		op:   m.expOp,
	}
	return m
}

func (m *opMatcher) After(item mockItem) RefOperationMatcher {
	m.expAfter = &expectedOp{
		item: item,
		op:   m.expOp,
	}
	return m
}

func (m *opMatcher) IsCreated() types.GomegaMatcher {
	if m.expBefore != nil {
		m.expBefore.op = operationCreate
	}
	if m.expAfter != nil {
		m.expAfter.op = operationCreate
	}
	return m
}

func (m *opMatcher) IsModified() types.GomegaMatcher {
	if m.expBefore != nil {
		m.expBefore.op = operationModify
	}
	if m.expAfter != nil {
		m.expAfter.op = operationModify
	}
	return m
}

func (m *opMatcher) IsDeleted() types.GomegaMatcher {
	if m.expBefore != nil {
		m.expBefore.op = operationDelete
	}
	if m.expAfter != nil {
		m.expAfter.op = operationDelete
	}
	return m
}

func (m *opMatcher) IsRecreated() types.GomegaMatcher {
	if m.expBefore != nil {
		m.expBefore.op = operationReCreate
	}
	if m.expAfter != nil {
		m.expAfter.op = operationReCreate
	}
	return m
}

func (m *opMatcher) IsBeingCreated() types.GomegaMatcher {
	if m.expBefore != nil {
		m.expBefore.op = operationCreate
		m.expBefore.inProgress = true
	}
	if m.expAfter != nil {
		m.expAfter.op = operationCreate
		m.expAfter.inProgress = true
	}
	return m
}

func (m *opMatcher) IsBeingDeleted() types.GomegaMatcher {
	if m.expBefore != nil {
		m.expBefore.op = operationDelete
		m.expBefore.inProgress = true
	}
	if m.expAfter != nil {
		m.expAfter.op = operationDelete
		m.expAfter.inProgress = true
	}
	return m
}

func (m *opMatcher) IsBeingModified() types.GomegaMatcher {
	if m.expBefore != nil {
		m.expBefore.op = operationModify
		m.expBefore.inProgress = true
	}
	if m.expAfter != nil {
		m.expAfter.op = operationModify
		m.expAfter.inProgress = true
	}
	return m
}

func (m *opMatcher) IsBeingRecreated() types.GomegaMatcher {
	if m.expBefore != nil {
		m.expBefore.op = operationReCreate
		m.expBefore.inProgress = true
	}
	if m.expAfter != nil {
		m.expAfter.op = operationReCreate
		m.expAfter.inProgress = true
	}
	return m
}
