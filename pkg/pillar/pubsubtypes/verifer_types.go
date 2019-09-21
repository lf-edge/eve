package pubsubtypes

import (
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"log"
)

type CallbackFn func(types.AppInstanceConfig) bool

type AppInstanceConfigPubSubBase struct {
	agentName string
	db        map[string]types.AppInstanceConfig
}

func (a AppInstanceConfigPubSubBase) GetItem(key string) types.AppInstanceConfig {
	return a.db[key]
}

func (a AppInstanceConfigPubSubBase) SetItem(key string, appInstanceConfig types.AppInstanceConfig) {
	a.db[key] = appInstanceConfig
	pubAppInstanceConfig, err := pubsub.Publish(a.agentName,
  	types.AppInstanceConfig{})
 	if err != nil {
  		log.Fatal(err)
  	}
}

func (a AppInstanceConfigPubSubBase) IterateDb(fn CallbackFn) {
	for _, value := range a.db {
	   retval := fn(value)
	   if retval == false {
	      break
	   }
	}
}

type AppInstanceConfigPub struct {
	base 	AppInstanceConfigPubSubBase
}

func (pub AppInstanceConfigPub) Publish() {
	pubsub.Publish(pub.base.agentName, types.AppInstanceConfig{})
}