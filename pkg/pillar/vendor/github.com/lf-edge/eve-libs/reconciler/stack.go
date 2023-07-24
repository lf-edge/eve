// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// A simple stack used for DFS graph traversal.

package reconciler

import (
	"fmt"

	dg "github.com/lf-edge/eve-libs/depgraph"
)

type stackElem struct {
	itemRef   dg.ItemRef
	postOrder bool
}

// stack is a simple LIFO queue for items to reconcile.
type stack struct {
	elems []stackElem
}

// newStack : returns a new instance of the stack.
func newStack() *stack {
	return &stack{
		elems: make([]stackElem, 0, 16),
	}
}

// isEmpty : will return a boolean indicating whether there are any elements on the stack.
func (s *stack) isEmpty() bool {
	return len(s.elems) == 0
}

// push : Adds an element on the stack.
func (s *stack) push(elem stackElem) *stack {
	s.elems = append(s.elems, elem)
	return s
}

// pop : removes an element from the stack and returns its value.
func (s *stack) pop() (stackElem, error) {
	if len(s.elems) == 0 {
		return stackElem{}, fmt.Errorf("stack is empty")
	}
	element := s.elems[len(s.elems)-1]
	s.elems = s.elems[:len(s.elems)-1]
	return element, nil
}
