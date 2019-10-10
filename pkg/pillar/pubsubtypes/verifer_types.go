package pubsubtypes

import (
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"log"
)

//CallbackFn : used in the iterate function to perform a function on the data
type CallbackFn func(types.AppInstanceConfig) bool

//AppInstanceConfigPubSubBase : stores data that both the pub and sub structures will need to use
type AppInstanceConfigPubSubBase struct {
	agentName string
	db        map[string]types.AppInstanceConfig
}

//Get : returns the data associated by a specific key in the db
func (config *AppInstanceConfigPubSubBase) Get(key string) types.AppInstanceConfig {
	if res, ok := config.db[key]; ok {
		return res
	} else {
		return types.AppInstanceConfig{}
	}
}

//Set : set a key to be associated with an appInstanceConfig
func (config *AppInstanceConfigPubSubBase) Set(key string, appInstanceConfig types.AppInstanceConfig) {
	config.db[key] = appInstanceConfig
	_, err := pubsub.Publish(config.agentName, types.AppInstanceConfig{})
	if err != nil {
		log.Fatal(err)
	}
}

//IterateDb : perfroms CallbackFn on the dataset
func (config *AppInstanceConfigPubSubBase) IterateDb(fn CallbackFn) {
	for _, value := range config.db {
		retval := fn(value)
		if retval == false {
			break
		}
	}
}

//AppInstanceConfigPub : has a publish function to publish AppInstanceConfig
type AppInstanceConfigPub struct {
	base AppInstanceConfigPubSubBase
}

//AppInstanceConfigPub : the publish function which takes data from base and publishes it
func (pub *AppInstanceConfigPub) Publish() {
	pubsub.Publish(pub.base.agentName, types.AppInstanceConfig{})
}
