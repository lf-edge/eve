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

func (config *AppInstanceConfigPubSubBase) Get(key string) types.AppInstanceConfig {
	return config.db[key]
}

func (config *AppInstanceConfigPubSubBase) Set(key string, appInstanceConfig types.AppInstanceConfig) {
	config.db[key] = appInstanceConfig
	_, err := pubsub.Publish(config.agentName, types.AppInstanceConfig{})
	if err != nil {
		log.Fatal(err)
	}
}

func (config *AppInstanceConfigPubSubBase) IterateDb(fn CallbackFn) {
	for _, value := range config.db {
		retval := fn(value)
		if retval == false {
			break
		}
	}
}

type AppInstanceConfigPub struct {
	base AppInstanceConfigPubSubBase
}

func (pub *AppInstanceConfigPub) Publish() {
	pubsub.Publish(pub.base.agentName, types.AppInstanceConfig{})
}
