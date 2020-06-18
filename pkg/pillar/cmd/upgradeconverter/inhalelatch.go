// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

// Inhale the persisted latch information for the app instances so we
// can tell the sha for the OCI volumes
// Note that we do not look at the latch in volumemgr since that is
// only for new volumes and content trees.

import (
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// All of the latches we found
type latch struct {
	latches []types.AppAndImageToHash
}

func inhaleLatch(ps *pubsub.PubSub) (latch, error) {
	log.Debugf("inhaleLatch()")
	var l latch

	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedmanager",
		Persistent: true,
		TopicType:  types.AppAndImageToHash{},
	})
	if err != nil {
		log.Error(err)
		return l, err
	}
	// The persistent publication has pulled in what is already published
	items := pub.GetAll()
	log.Debugf("inhaleLatch found %d", len(items))
	for _, item := range items {
		aih := item.(types.AppAndImageToHash)
		l.latches = append(l.latches, aih)
	}
	return l, err
}

// lookup returns nil if not found
func (l *latch) lookup(appInstID uuid.UUID, imageID uuid.UUID, purgeCounter uint32) *types.AppAndImageToHash {
	for i := range l.latches {
		aih := &l.latches[i]
		if aih.AppUUID == appInstID && aih.ImageID == imageID &&
			aih.PurgeCounter == purgeCounter {
			log.Debugf("latch.lookup found appInstID %s imageID %s purgeCounter %d",
				appInstID, imageID, purgeCounter)
			return aih
		}
	}
	log.Debugf("latch.lookup NOT found appInstID %s imageID %s purgeCounter %d",
		appInstID, imageID, purgeCounter)
	return nil
}
