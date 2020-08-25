package pubsub

import (
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

type notifyName struct {
	name     string // From pub.nameString()
	instance int
	ch       chan<- Notify
}

// Updaters list of channels to which notifications should be sent. Global
// across an entire `PubSub struct`. Can `Add()` and `Remove()`.
type Updaters struct {
	lock    sync.Mutex
	servers []notifyName
}

// Add an updater
func (u *Updaters) Add(log *base.LogObject, updater chan Notify, name string, instance int) {
	u.lock.Lock()
	nn := notifyName{name: name, instance: instance, ch: updater}
	u.servers = append(u.servers, nn)
	u.lock.Unlock()
}

// Remove an updater
func (u *Updaters) Remove(log *base.LogObject, updater chan Notify) {
	u.lock.Lock()
	// A new slice which points to the same underlying array
	servers := u.servers[:0]
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
