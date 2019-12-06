package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/cast"
	log "github.com/sirupsen/logrus"
)

type downloadHandler struct {
	// We have one goroutine per provisioned domU object.
	// Channel is used to send config (new and updates)
	// Channel is closed when the object is deleted
	// The go-routine owns writing status for the object
	// The key in the map is the objects Key().

	handlers map[string]chan<- interface{}
}

func makeDownloadHandler() *downloadHandler {
	return &downloadHandler{
		handlers: make(map[string]chan<- interface{}),
	}
}

// Wrappers around createObject, modifyObject, and deleteObject

// Determine whether it is an create or modify
func (d *downloadHandler) modify(ctxArg interface{}, objType string,
	key string, configArg interface{}) {

	log.Infof("downloadHandler.modify(%s)\n", key)
	config := cast.CastDownloaderConfig(configArg)
	if config.Key() != key {
		log.Errorf("downloadHandler.modify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	h, ok := d.handlers[config.Key()]
	if !ok {
		log.Fatalf("downloadHandler.modify called on config that does not exist")
	}
	h <- configArg
}

func (d *downloadHandler) create(ctxArg interface{}, objType string,
	key string, configArg interface{}) {

	log.Infof("downloadHandler.create(%s)\n", key)
	ctx := ctxArg.(*downloaderContext)
	config := cast.CastDownloaderConfig(configArg)
	if config.Key() != key {
		log.Errorf("downloadHandler.create key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	h, ok := d.handlers[config.Key()]
	if ok {
		log.Fatalf("downloadHandler.create called on config that already exists")
	}
	h1 := make(chan interface{}, 1)
	d.handlers[config.Key()] = h1
	go runHandler(ctx, objType, key, h1)
	h = h1
	h <- configArg
}

func (d *downloadHandler) delete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("downloadHandler.delete(%s)\n", key)
	// Do we have a channel/goroutine?
	h, ok := d.handlers[key]
	if ok {
		log.Debugf("Closing channel\n")
		close(h)
		delete(d.handlers, key)
	} else {
		log.Debugf("downloadHandler.delete: unknown %s\n", key)
		return
	}
	log.Infof("downloadHandler.delete(%s) done\n", key)
}
