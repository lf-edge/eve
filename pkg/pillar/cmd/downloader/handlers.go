package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// Notify simple struct to pass notification messages
type Notify struct{}

type downloadHandler struct {
	// We have one goroutine per provisioned domU object.
	// Channel is used to send notifications about config (add and updates)
	// Channel is closed when the object is deleted
	// The go-routine owns writing status for the object
	// The key in the map is the objects Key().

	handlers map[string]chan<- Notify
}

func makeDownloadHandler() *downloadHandler {
	return &downloadHandler{
		handlers: make(map[string]chan<- Notify),
	}
}

// Wrappers around createObject, modifyObject, and deleteObject

// Determine whether it is an create or modify
func (d *downloadHandler) modify(ctxArg interface{}, objType string,
	key string, configArg interface{}) {

	log.Infof("downloadHandler.modify(%s)", key)
	config := configArg.(types.DownloaderConfig)
	h, ok := d.handlers[config.Key()]
	if !ok {
		log.Fatalf("downloadHandler.modify called on config that does not exist")
	}
	select {
	case h <- Notify{}:
		log.Infof("downloadHandler.modify(%s) sent notify", key)
	default:
		// handler is slow
		log.Warnf("downloadHandler.modify(%s) NOT sent notify. Slow handler?", key)
	}
}

func (d *downloadHandler) create(ctxArg interface{}, objType string,
	key string, configArg interface{}) {

	log.Infof("downloadHandler.create(%s)", key)
	ctx := ctxArg.(*downloaderContext)
	config := configArg.(types.DownloaderConfig)
	h, ok := d.handlers[config.Key()]
	if ok {
		log.Fatalf("downloadHandler.create called on config that already exists")
	}
	h1 := make(chan Notify, 1)
	d.handlers[config.Key()] = h1
	go runHandler(ctx, objType, key, h1)
	h = h1
	select {
	case h <- Notify{}:
		log.Infof("downloadHandler.create(%s) sent notify", key)
	default:
		// Shouldn't happen since we just created channel
		log.Fatalf("downloadHandler.create(%s) NOT sent notify", key)
	}
}

func (d *downloadHandler) delete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("downloadHandler.delete(%s)", key)
	// Do we have a channel/goroutine?
	h, ok := d.handlers[key]
	if ok {
		log.Debugf("Closing channel")
		close(h)
		delete(d.handlers, key)
	} else {
		log.Debugf("downloadHandler.delete: unknown %s", key)
		return
	}
	log.Infof("downloadHandler.delete(%s) done", key)
}
