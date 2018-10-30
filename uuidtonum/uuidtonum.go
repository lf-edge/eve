// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package uuidtonum

import (
	"errors"
	"fmt"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"time"
)

// Update LastUseTime; assert InUse true
func UuidToNumUpdate(pub *pubsub.Publication, uuid uuid.UUID, number int) {

	log.Infof("UuidToNumUpdate(%s, %d)\n", uuid.String(), number)
	i, err := pub.Get(uuid.String())
	if err != nil {
		// XXX fatal
		log.Errorf("UuidToNumUpdate(%s) does not exist\n",
			uuid.String())
		return
	}
	u := cast.CastUuidToNum(i)
	if !u.InUse {
		// XXX fatal
		log.Errorf("UuidToNumUpdate(%s) not InUse %v\n",
			uuid.String(), u)
		return
	}
	if u.Number != number {
		// XXX fatal
		log.Errorf("UuidToNumUpdate(%s) number mismatch %v vs. %d\n",
			uuid.String(), u, number)
		return
	}
	u.LastUseTime = time.Now()
	log.Infof("UuidToNumUpdate(%s) publishing updated %v\n",
		uuid.String(), u)
	if err := pub.Publish(u.Key(), u); err != nil {
		// XXX fatal
		log.Errorf("UuidToNumUpdate(%s) publish failed %v\n",
			uuid.String(), err)
	}
}

// Update LastUseTime; set CreateTime if no entry, set InUse
// If mustCreate is set the entry should not exist.
func UuidToNumAllocate(pub *pubsub.Publication, uuid uuid.UUID,
	number int, mustCreate bool, numType string) {

	log.Infof("UuidToNumAllocate(%s, %d, %v)\n", uuid.String(), number,
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
		log.Infof("UuidToNumAllocate(%s) publishing created %v\n",
			uuid.String(), u)
		pub.Publish(u.Key(), u)
		return
	}
	u := cast.CastUuidToNum(i)
	if u.NumType != numType {
		// XXX fatal
		log.Errorf("UuidToNumAllocate(%s) wrong numType %s vs. %s\n",
			uuid.String(), u.NumType, numType)
		return
	}
	if u.Number != number {
		// XXX fatal
		log.Errorf("UuidToNumAllocate(%s) number mismatch %v vs. %d\n",
			uuid.String(), u, number)
		return
	}
	if mustCreate {
		// XXX fatal
		log.Errorf("UuidToNumAllocate(%s) already exists %v\n",
			uuid.String(), u)
		return
	}
	if u.InUse {
		// XXX fatal
		log.Errorf("UuidToNumAllocate(%s) already InUse %v\n",
			uuid.String(), u)
	}
	u.InUse = true
	u.LastUseTime = time.Now()
	log.Infof("UuidToNumAllocate(%s) publishing updated %v\n",
		uuid.String(), u)
	if err := pub.Publish(u.Key(), u); err != nil {
		// XXX fatal
		log.Errorf("UuidToNumAllocate(%s) publish failed %v\n",
			uuid.String(), err)
	}
}

// Clear InUse
func UuidToNumFree(pub *pubsub.Publication, uuid uuid.UUID) {

	log.Infof("UuidToNumFree(%s)\n", uuid.String())
	i, err := pub.Get(uuid.String())
	if err != nil {
		// XXX fatal
		log.Errorf("UuidToNumFree(%s) does not exist\n", uuid.String())
		return
	}
	u := cast.CastUuidToNum(i)
	u.InUse = false
	u.LastUseTime = time.Now()
	log.Infof("UuidToNumFree(%s) publishing updated %v\n",
		uuid.String(), u)
	if err := pub.Publish(u.Key(), u); err != nil {
		// XXX fatal
		log.Errorf("UuidToNumFree(%s) publish failed %v\n",
			uuid.String(), err)
	}
}

func UuidToNumDelete(pub *pubsub.Publication, uuid uuid.UUID) {

	log.Infof("UuidToNumDelete(%s)\n", uuid.String())
	_, err := pub.Get(uuid.String())
	if err != nil {
		// XXX fatal
		log.Errorf("UuidToNumDelete(%s) does not exist\n", uuid.String())
		return
	}
	if err := pub.Unpublish(uuid.String()); err != nil {
		// XXX fatal
		log.Errorf("UuidToNumDelete(%s) unpublish failed %v\n",
			uuid.String(), err)
	}
}

func UuidToNumGet(pub *pubsub.Publication, uuid uuid.UUID,
	numType string) (int, error) {

	key := uuid.String()
	log.Infof("UuidToNumGet(%s, %s)\n", key, numType)
	i, err := pub.Get(key)
	if err != nil {
		return 0, err
	}
	u := cast.CastUuidToNum(i)
	if u.Key() != key {
		errStr := fmt.Sprintf("UuidToNumGet key/UUID mismatch %s vs %s; ignored %+v",
			key, u.Key(), u)
		log.Errorln(errStr)
		return 0, errors.New(errStr)
	}
	log.Infof("UuidToNumGet(%s, %s) found %v\n", key, numType, u)
	return u.Number, nil
}
