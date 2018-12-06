package sema

import (
	log "github.com/sirupsen/logrus"
)

type empty interface{}
type Semaphore chan empty

func Create(n int) Semaphore {
	log.Infof("sema.create()\n")
	return make(Semaphore, n)
}

// Acquire n resources
func (s Semaphore) P(n int) {
	log.Infof("sema.P(%d)\n", n)
	var e empty
	for i := 0; i < n; i++ {
		s <- e
	}
	log.Infof("sema.P(%d) done\n", n)
}

// Release n resources
func (s Semaphore) V(n int) {
	log.Infof("sema.V(%d)\n", n)
	for i := 0; i < n; i++ {
		<-s
	}
	log.Infof("sema.V(%d) done\n", n)
}
