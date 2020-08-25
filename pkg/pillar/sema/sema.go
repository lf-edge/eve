// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package sema

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
)

type empty interface{}

// Semaphore is our representation of a semaphore
type Semaphore struct {
	c   chan empty
	log *base.LogObject
}

// New returns a Semaphore object
func New(log *base.LogObject, n int) *Semaphore {
	log.Infof("sema.New()")
	return &Semaphore{
		c:   make(chan empty, n),
		log: log,
	}

}

// Acquire n resources
func (s *Semaphore) P(n int) {
	s.log.Infof("sema.P(%d)", n)
	var e empty
	for i := 0; i < n; i++ {
		s.c <- e
	}
	s.log.Infof("sema.P(%d) done", n)
}

// Release n resources
func (s *Semaphore) V(n int) {
	s.log.Infof("sema.V(%d)", n)
	for i := 0; i < n; i++ {
		<-s.c
	}
	s.log.Infof("sema.V(%d) done", n)
}
