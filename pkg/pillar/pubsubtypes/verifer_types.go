package pubsubtypes

import (
	"github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

type CallbackFn func() bool

type AppInstanceConfigPubSubBase struct {
	agentName string
	db        map[string]types.AppInstanceConfig
}

func (a AppInstanceConfigPubSubBase) GetItem(string key) {
	return db[key]
}

func (a AppInstanceConfigPubSubBase) SetItem(string key, types.AppInstanceConfig appInstanceConfig) {
	db[key] = appInstanceConfig
	pubAppInstanceConfig, err := pubsub.Publish(agentName,
  	types.AppInstanceConfig{})
 	if err != nil {
  		log.Fatal(err)
  	}
}


func (a AppInstanceConfigPubSubBase) IterateDb(func CallbackFn)
	for key,value range := a.db {
	   retval := CallbackFn( value)
	   if retval == false {
	      break
	   }
	}
}
