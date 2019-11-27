package pubsub

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

type notifyName struct {
	name     string // From pub.nameString()
	instance int
	ch       chan<- Notify
}

// The set of channels to which we need to send notifications
type Updaters struct {
	lock    sync.Mutex
	servers []notifyName
}

// Add an updater
func (u *Updaters) Add(updater chan Notify, name string, instance int) {
	u.lock.Lock()
	nn := notifyName{name: name, instance: instance, ch: updater}
	u.servers = append(u.servers, nn)
	u.lock.Unlock()
}

// Remove an updater
func (u *Updaters) Remove(updater chan Notify) {
	u.lock.Lock()
	servers := make([]notifyName, len(u.servers))
	found := false
	for _, old := range u.servers {
		if old.ch == updater {
			found = true
		} else {
			servers = append(servers, old)
		}
	}
	if !found {
		log.Fatal("updaters.remove(): not found\n")
	}
	u.servers = servers
	u.lock.Unlock()
}
