// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package uuidtonum

import (
	"errors"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/satori/go.uuid"
)

// Update LastUseTime; set CreateTime if no entry, set InUse
// The number can be updated as part of this. Entry could already be InUse
// If mustCreate is set the entry should not exist.
// XXX doesn't allocate; merely reserves the number for the UUID
func UuidToNumAllocate(log *base.LogObject, pub pubsub.Publication, uuid uuid.UUID,
	number int, mustCreate bool, numType string) {

	log.Functionf("UuidToNumAllocate(%s, %d, %v)\n", uuid.String(), number,
		mustCreate)
	i, err := pub.Get(uuid.String())
	if err != nil {
		now := time.Now()
		u := types.UuidToNum{UUID: uuid,
			CreateTime:  now,
			LastUseTime: now,
			InUse:       true,
			NumType:     numType,
			Number:      number,
		}
		log.Functionf("UuidToNumAllocate(%s) publishing created %v\n",
			uuid.String(), u)
		pub.Publish(u.Key(), u)
		return
	}
	u := i.(types.UuidToNum)
	if u.NumType != numType {
		log.Fatalf("UuidToNumAllocate(%s) wrong numType %s vs. %s\n",
			uuid.String(), u.NumType, numType)
	}
	if mustCreate {
		log.Fatalf("UuidToNumAllocate(%s) already exists %v\n",
			uuid.String(), u)
	}
	if u.Number != number {
		log.Warnf("UuidToNumAllocate(%s) number changing from %d to %d\n",
			uuid.String(), u.Number, number)
	}
	if u.InUse {
		log.Warnf("UuidToNumAllocate(%s) already InUse %v\n",
			uuid.String(), u)
	}
	u.Number = number
	u.InUse = true
	u.LastUseTime = time.Now()
	// XXX note that nothing but lastusetime might be updated! Improve log?
	log.Functionf("UuidToNumAllocate(%s) publishing updated %v\n",
		uuid.String(), u)
	if err := pub.Publish(u.Key(), u); err != nil {
		log.Fatalf("UuidToNumAllocate(%s) publish failed %v\n",
			uuid.String(), err)
	}
}

// Clear InUse
func UuidToNumFree(log *base.LogObject, pub pubsub.Publication, uuid uuid.UUID) {

	log.Functionf("UuidToNumFree(%s)\n", uuid.String())
	i, err := pub.Get(uuid.String())
	if err != nil {
		log.Fatalf("UuidToNumFree(%s) does not exist\n", uuid.String())
	}
	u := i.(types.UuidToNum)
	u.InUse = false
	u.LastUseTime = time.Now()
	log.Functionf("UuidToNumFree(%s) publishing updated %v\n",
		uuid.String(), u)
	if err := pub.Publish(u.Key(), u); err != nil {
		log.Fatalf("UuidToNumFree(%s) publish failed %v\n",
			uuid.String(), err)
	}
}

func UuidToNumDelete(log *base.LogObject, pub pubsub.Publication, uuid uuid.UUID) {

	log.Functionf("UuidToNumDelete(%s)\n", uuid.String())
	_, err := pub.Get(uuid.String())
	if err != nil {
		log.Fatalf("UuidToNumDelete(%s) does not exist\n",
			uuid.String())
	}
	if err := pub.Unpublish(uuid.String()); err != nil {
		log.Fatalf("UuidToNumDelete(%s) unpublish failed %v\n",
			uuid.String(), err)
	}
}

func UuidToNumGet(log *base.LogObject, pub pubsub.Publication, uuid uuid.UUID,
	numType string) (int, error) {

	key := uuid.String()
	log.Functionf("UuidToNumGet(%s, %s)\n", key, numType)
	i, err := pub.Get(key)
	if err != nil {
		return 0, err
	}
	u := i.(types.UuidToNum)
	log.Functionf("UuidToNumGet(%s, %s) found %v\n", key, numType, u)
	return u.Number, nil
}

func UuidToNumGetOldestUnused(log *base.LogObject, pub pubsub.Publication,
	numType string) (uuid.UUID, int, error) {

	log.Functionf("UuidToNumGetOldestUnused(%s)\n", numType)

	// Will have a LastUseTime of zero
	oldest := new(types.UuidToNum)
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.UuidToNum)
		if status.NumType != numType || status.InUse {
			continue
		}
		if oldest.LastUseTime.Before(status.LastUseTime) {
			log.Functionf("UuidToNumGetOldestUnused(%s) found older %v\n",
				numType, status)
			oldest = &status
		}
	}
	if oldest.LastUseTime.IsZero() {
		errStr := fmt.Sprintf("UuidToNumGetOldestUnused(%s) none found",
			numType)
		return uuid.UUID{}, 0, errors.New(errStr)
	}
	log.Functionf("UuidToNumGetOldestUnused(%s) found %v\n", numType, oldest)
	return oldest.UUID, oldest.Number, nil
}
