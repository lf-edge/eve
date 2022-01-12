// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// UUIDPairToNum used for appNum on network instance
type UUIDPairToNum struct {
	BaseID      uuid.UUID
	AppID       uuid.UUID
	Number      int
	NumType     string
	CreateTime  time.Time
	LastUseTime time.Time
	InUse       bool
}

// Key is the key in pubsub
func (info UUIDPairToNum) Key() string {
	return fmt.Sprintf("%s-%s", info.BaseID.String(), info.AppID.String())
}

func convertUUIDPairToNum(ctxPtr *ucContext) error {

	pubUUIDPairToNum, err := ctxPtr.ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedrouter",
		Persistent: true,
		TopicType:  UUIDPairToNum{},
	})

	if err != nil {
		log.Error(err)
		return err
	}
	defer pubUUIDPairToNum.Close()

	pubUUIDPairAndIfIdxToNum, err := ctxPtr.ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedrouter",
		Persistent: true,
		TopicType:  types.UUIDPairAndIfIdxToNum{},
	})

	if err != nil {
		log.Error(err)
		return err
	}
	defer pubUUIDPairAndIfIdxToNum.Close()

	items := pubUUIDPairToNum.GetAll()
	if len(items) == 0 {
		log.Trace("UUIDPairToNum not found")
		return nil
	}

	log.Tracef("UUIDPairToNum found %d", len(items))

	// if we have UUIDPairToNum assume that we should remove old items and recreate them
	olditems := pubUUIDPairAndIfIdxToNum.GetAll()
	for key := range olditems {
		err = pubUUIDPairAndIfIdxToNum.Unpublish(key)
		if err != nil {
			log.Error(err)
		}
	}

	for _, item := range items {
		uptn := item.(UUIDPairToNum)
		upitn := types.UUIDPairAndIfIdxToNum{
			BaseID:      uptn.BaseID,
			AppID:       uptn.AppID,
			Number:      uptn.Number,
			NumType:     uptn.NumType,
			CreateTime:  uptn.CreateTime,
			LastUseTime: uptn.LastUseTime,
			InUse:       uptn.InUse,
			IfIdx:       0,
		}
		// publish new allocator
		err = pubUUIDPairAndIfIdxToNum.Publish(upitn.Key(), upitn)
		if err != nil {
			log.Error(err)
			continue
		}
		// unpublish old allocator
		err = pubUUIDPairToNum.Unpublish(uptn.Key())
		if err != nil {
			log.Error(err)
		}
	}

	return nil
}
