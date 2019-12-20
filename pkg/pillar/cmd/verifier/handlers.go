package verifier

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

type verifyHandler struct {
	// We have one goroutine per provisioned domU object.
	// Channel is used to send config (new and updates)
	// Channel is closed when the object is deleted
	// The go-routine owns writing status for the object
	// The key in the map is the objects Key()

	handlers map[string]chan<- interface{}
}

func makeVerifyHandler() *verifyHandler {
	return &verifyHandler{
		handlers: make(map[string]chan<- interface{}),
	}
}

// Wrappers around handleCreate, handleModify, and handleDelete

// Determine whether it is an create or modify
func (v *verifyHandler) modify(ctxArg interface{}, objType string,
	key string, configArg interface{}) {

	log.Infof("verifyHandler.modify(%s)\n", key)
	config := configArg.(types.VerifyImageConfig)
	h, ok := v.handlers[config.Key()]
	if !ok {
		log.Fatalf("verifyHandler.modify called on config that does not exist")
	}
	h <- configArg
	log.Infof("verifyHandler.modify(%s) done\n", key)
}

func (v *verifyHandler) create(ctxArg interface{}, objType string,
	key string, configArg interface{}) {

	log.Infof("verifyHandler.create(%s)\n", key)
	ctx := ctxArg.(*verifierContext)
	config := configArg.(types.VerifyImageConfig)
	h, ok := v.handlers[config.Key()]
	if ok {
		log.Fatalf("verifyHandler.create called on config that already exists")
	}
	h1 := make(chan interface{}, 1)
	v.handlers[config.Key()] = h1
	go runHandler(ctx, objType, key, h1)
	h = h1
	h <- configArg
	log.Infof("verifyHandler.create(%s) done\n", key)
}

func (v *verifyHandler) delete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("verifyHandler.delete(%s)\n", key)
	// Do we have a channel/goroutine?
	h, ok := v.handlers[key]
	if ok {
		log.Debugf("Closing channel\n")
		close(h)
		delete(v.handlers, key)
	} else {
		log.Debugf("verifyHandler.delete: unknown %s\n", key)
		return
	}
	log.Infof("verifyHandler.delete(%s) done\n", key)
}
