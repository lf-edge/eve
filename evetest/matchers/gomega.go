// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package matchers

import (
	"fmt"

	"github.com/lf-edge/eve/evetest"
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
)

// PredicateMatcher is a generic gomega matcher that applies a predicate to a
// value of type T and uses T's String() method to produce readable failure
// messages (instead of gomega's default deep struct dump).
type PredicateMatcher[T fmt.Stringer] struct {
	description string
	predicate   func(T) bool
	stopIf      func(T) (string, bool)
}

// SatisfyPredicate returns a gomega matcher that applies the given predicate
// to a value of type T. On failure, it prints the description and the value's
// String() representation.
//
// Example usage with Receive:
//
//	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
//		"state is ONLINE",
//		func(info *eveinfo.ZInfoNetworkInstance) bool {
//			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
//		})))
func SatisfyPredicate[T fmt.Stringer](description string,
	predicate func(T) bool) *PredicateMatcher[T] {
	evetest.Logger().Infof("Waiting for: %s...", description)
	return &PredicateMatcher[T]{
		description: description,
		predicate:   predicate,
	}
}

// StopIf sets a condition that, when true, causes Eventually to abort
// immediately instead of waiting for the timeout. This is useful when the
// value reaches a terminal state (e.g., error) that makes further polling
// pointless.
func (m *PredicateMatcher[T]) StopIf(
	cond func(T) (reason string, stop bool)) types.GomegaMatcher {
	m.stopIf = cond
	return m
}

// Match checks whether actual (which must be of type T) satisfies the
// predicate. If a StopIf condition was set and it fires, Match returns a
// gomega.StopTrying error to abort Eventually immediately.
func (m *PredicateMatcher[T]) Match(actual any) (bool, error) {
	val, ok := actual.(T)
	if !ok {
		var zero T
		return false, fmt.Errorf(
			"SatisfyPredicate expects %T, got %T", zero, actual)
	}
	if m.stopIf != nil {
		reason, stop := m.stopIf(val)
		if stop {
			return false, gomega.StopTrying(
				fmt.Sprintf("Stop waiting for: %s\n%s\n%s",
					m.description, reason, val.String()))
		}
	}
	return m.predicate(val), nil
}

// FailureMessage returns a human-readable message when the predicate is not
// satisfied. It includes the description and the value's String() output.
func (m *PredicateMatcher[T]) FailureMessage(actual any) string {
	return fmt.Sprintf("Expected to satisfy: %s\n%s",
		m.description, actual.(T).String())
}

// NegatedFailureMessage returns a human-readable message when the predicate
// is unexpectedly satisfied (for use with ShouldNot/ToNot).
func (m *PredicateMatcher[T]) NegatedFailureMessage(actual any) string {
	return fmt.Sprintf("Expected NOT to satisfy: %s\n%s",
		m.description, actual.(T).String())
}
