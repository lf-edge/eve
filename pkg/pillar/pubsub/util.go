package pubsub

import (
	"encoding/json"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
)

func deepCopy(in interface{}) interface{} {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal("json Marshal in deepCopy", err)
	}
	var output interface{}
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in deepCopy")
	}
	return output
}

func lookupSlave(slaveCollection LocalCollection, key string) *interface{} {
	for slaveKey := range slaveCollection {
		if slaveKey == key {
			res := slaveCollection[slaveKey]
			return &res
		}
	}
	return nil
}

// TypeToName given a particular object, get the desired name for it
func TypeToName(something interface{}) string {
	t := reflect.TypeOf(something)
	out := strings.Split(t.String(), ".")
	return out[len(out)-1]
}
