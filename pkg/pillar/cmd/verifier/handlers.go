package verifier

import (
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	log "github.com/sirupsen/logrus"
)

// Notify simple struct to pass notification messages
type Notify struct{}

type verifyHandler struct {
	// We have one goroutine per provisioned domU object.
	// Channel is used to send notifications about config (add and updates)
	// Channel is closed when the object is deleted
	// The go-routine owns writing status for the object
	// The key in the map is the objects Key()

	handlers map[string]chan<- Notify
}

func makeVerifyHandler() *verifyHandler {
	return &verifyHandler{
		handlers: make(map[string]chan<- Notify),
	}
}

// Wrappers around handleCreate, handleModify, and handleDelete

// Determine whether it is an create or modify
func (v *verifyHandler) modify(ctxArg interface{}, objType string,
	key string, configArg interface{}) {

	log.Infof("verifyHandler.modify(%s)\n", key)
	h, ok := v.handlers[key]
	if !ok {
		log.Fatalf("verifyHandler.modify called on config that does not exist")
	}
	select {
	case h <- Notify{}:
		log.Infof("verifyHandler.modify(%s) sent notify", key)
	default:
		// handler is slow
		log.Warnf("verifyHandler.modify(%s) NOT sent notify. Slow handler?", key)
	}
	log.Infof("verifyHandler.modify(%s) done\n", key)
}

func (v *verifyHandler) create(ctxArg interface{}, objType string,
	key string, configArg interface{}) {

	log.Infof("verifyHandler.create(%s)\n", key)
	ctx := ctxArg.(*verifierContext)
	h, ok := v.handlers[key]
	if ok {
		log.Fatalf("verifyHandler.create called on config that already exists")
	}
	h1 := make(chan Notify, 1)
	v.handlers[key] = h1
	typeName := pubsub.TypeToName(configArg)
	switch typeName {
	case "VerifyImageConfig":
		go runHandler(ctx, objType, key, h1)
	case "PersistImageConfig":
		go runPersistHandler(ctx, objType, key, h1)
	default:
		log.Fatalf("Unknown type %s", typeName)
	}
	h = h1
	select {
	case h <- Notify{}:
		log.Infof("verifyHandler.create(%s) sent notify", key)
	default:
		// Shouldn't happen since we just created channel
		log.Fatalf("verifyHandler.create(%s) NOT sent notify", key)
	}
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
