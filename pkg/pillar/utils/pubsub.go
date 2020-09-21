package utils

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"

	log "github.com/sirupsen/logrus"
)

// LookupDatastoreConfig get a datastore config based on uuid
func LookupDatastoreConfig(sub pubsub.Subscription, dsID uuid.UUID) (*types.DatastoreConfig, error) {

	if dsID == nilUUID {
		err := fmt.Errorf("lookupDatastoreConfig(%s): No datastore ID", dsID.String())
		log.Errorln(err)
		return nil, err
	}
	cfg, err := sub.Get(dsID.String())
	if err != nil {
		err2 := fmt.Errorf("lookupDatastoreConfig(%s) error: %v",
			dsID.String(), err)
		log.Errorln(err2)
		return nil, err2
	}
	dst := cfg.(types.DatastoreConfig)
	return &dst, nil
}
