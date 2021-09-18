// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package uuidpairtonum

import (
	"errors"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/satori/go.uuid"
)

// NumGet : return the number for a given UUID pair
func NumGet(log *base.LogObject, pub pubsub.Publication,
	baseID uuid.UUID, appID uuid.UUID, numType string) (int, error) {
	key := types.UUIDPairToNumKey(baseID, appID)
	log.Functionf("NumGet(%s, %s)", key, numType)
	i, err := pub.Get(key)
	if err != nil {
		return -1, err
	}
	u := i.(types.UUIDPairToNum)
	return u.Number, nil
}

// NumAllocate : stores the number for a given UUID pair
func NumAllocate(log *base.LogObject, pub pubsub.Publication,
	baseID uuid.UUID, appID uuid.UUID, appNum int, mustCreate bool,
	numType string) {
	log.Functionf("NumAllocate(%s, %s, %d, %v)", baseID.String(),
		appID.String(), appNum, mustCreate)
	now := time.Now()
	key := types.UUIDPairToNumKey(baseID, appID)
	i, err := pub.Get(key)
	if err != nil {
		u := types.UUIDPairToNum{
			BaseID:      baseID,
			AppID:       appID,
			CreateTime:  now,
			LastUseTime: now,
			InUse:       true,
			NumType:     numType,
			Number:      appNum,
		}
		log.Functionf("NumAllocate(%s) publishing %v",
			key, u)
		pub.Publish(u.Key(), u)
		return
	}
	u := i.(types.UUIDPairToNum)
	if u.NumType != numType {
		log.Fatalf("NumAllocate(%s) wrong numType %s vs. %s",
			key, u.NumType, numType)
	}
	if mustCreate {
		log.Fatalf("NumAllocate(%s) already exists %v",
			key, u)
	}
	if u.Number != appNum {
		log.Warnf("NumAllocate(%s) number changing from %d to %d",
			key, u.Number, appNum)
	}
	if u.InUse {
		log.Warnf("NumAllocate(%s) already InUse %v",
			key, u)
	}
	u.Number = appNum
	u.InUse = true
	u.LastUseTime = time.Now()
	// XXX note that nothing but lastusetime might be updated! Improve log?
	log.Functionf("NumAllocate(%s) publishing updated %v",
		key, u)
	if err := pub.Publish(u.Key(), u); err != nil {
		// Could be low on disk space
		log.Errorf("NumAllocate(%s) publish failed %v",
			key, err)
	}
	return
}

// NumFree : Clears InUse flag
func NumFree(log *base.LogObject, pub pubsub.Publication,
	baseID uuid.UUID, appID uuid.UUID) {
	key := types.UUIDPairToNumKey(baseID, appID)
	i, err := pub.Get(key)
	if err != nil {
		log.Fatalf("NumFree(%s) does not exist", key)
	}
	u := i.(types.UUIDPairToNum)
	u.InUse = false
	u.LastUseTime = time.Now()
	log.Functionf("NumFree(%s) publishing updated %v",
		key, u)
	if err := pub.Publish(u.Key(), u); err != nil {
		// Could be low on disk space
		log.Errorf("NumFree(%s) publish failed %v",
			key, err)
	}
}

// NumDelete : Removes the integer map for a given UUID pair
func NumDelete(log *base.LogObject, pub pubsub.Publication,
	baseID uuid.UUID, appID uuid.UUID) {
	key := types.UUIDPairToNumKey(baseID, appID)
	_, err := pub.Get(key)
	if err != nil {
		log.Fatalf("NumDelete(%s) does not exist", key)
	}
	log.Functionf("NumDelete(%s) unpublishing", key)
	if err := pub.Unpublish(key); err != nil {
		log.Fatalf("NumDelete(%s) unpublish failed %v", key, err)
	}
}

// NumGetOldestUnused : returns a number, not recently in use
func NumGetOldestUnused(log *base.LogObject, pub pubsub.Publication,
	baseID uuid.UUID, numType string) (uuid.UUID, int, error) {
	log.Functionf("NumGetOldestUnused(%s)", numType)
	// Will have a LastUseTime of zero
	oldest := new(types.UUIDPairToNum)
	items := pub.GetAll()
	for _, st := range items {
		item := st.(types.UUIDPairToNum)
		if item.NumType != numType || item.InUse || item.BaseID != baseID {
			continue
		}
		if oldest.LastUseTime.IsZero() ||
			oldest.LastUseTime.After(item.LastUseTime) {
			log.Functionf("NumGetOldestUnused(%s) found older %v",
				numType, item)
			oldest = &item
		}
	}
	if oldest.LastUseTime.IsZero() {
		errStr := fmt.Sprintf("NumGetOldestUnused(%s) none found",
			numType)
		return uuid.UUID{}, 0, errors.New(errStr)
	}
	log.Functionf("NumGetOldestUnused(%s) found %v", numType, oldest)
	return oldest.AppID, oldest.Number, nil
}
