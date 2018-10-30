// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package zedrouter

import (
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"time"
)

// Update LastUseTime; assert InUse true
func UuidToNumUpdate(ctx *zedrouterContext, uuid uuid.UUID, number int) {

	log.Infof("UuidToNumUpdate(%s, %d)\n", uuid.String(), number)
	pub := ctx.pubUuidToNum
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
	pub.Publish(u.Key(), u)
}

// Update LastUseTime; set CreateTime if no entry, set InUse
// If mustCreate is set the entry should not exist.
func UuidToNumAllocate(ctx *zedrouterContext, uuid uuid.UUID,
	number int, mustCreate bool, numType string) {

	log.Infof("UuidToNumAllocate(%s, %d, %v)\n", uuid.String(), number,
		mustCreate)
	pub := ctx.pubUuidToNum
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
	pub.Publish(u.Key(), u)
}

// Clear InUse
func UuidToNumFree(ctx *zedrouterContext, uuid uuid.UUID) {

	log.Infof("UuidToNumFree(%s)\n", uuid.String())

	pub := ctx.pubUuidToNum
	i, err := pub.Get(uuid.String())
	if err != nil {
		// XXX fatal
		log.Errorf("UuidToNumFree(%s) does not exist\n", uuid.String())
		return
	}
	u := cast.CastUuidToNum(i)
	u.InUse = false
	u.LastUseTime = time.Now()
	pub.Publish(u.Key(), u)
}
