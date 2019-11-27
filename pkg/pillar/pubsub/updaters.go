package pubsub

import (
	"log"
	"sync"
)

type notify struct{}

// The set of channels to which we need to send notifications
type updaters struct {
	lock    sync.Mutex
	servers []notifyName
}

type notifyName struct {
	name     string // From pub.nameString()
	instance int
	ch       chan<- notify
}

var updaterList updaters

func updatersAdd(updater chan notify, name string, instance int) {
	updaterList.lock.Lock()
	nn := notifyName{name: name, instance: instance, ch: updater}
	updaterList.servers = append(updaterList.servers, nn)
	updaterList.lock.Unlock()
}

func updatersRemove(updater chan notify) {
	updaterList.lock.Lock()
	servers := make([]notifyName, len(updaterList.servers))
	found := false
	for _, old := range updaterList.servers {
		if old.ch == updater {
			found = true
		} else {
			servers = append(servers, old)
		}
	}
	if !found {
		log.Fatal("updatersRemove: not found\n")
	}
	updaterList.servers = servers
	updaterList.lock.Unlock()
}
