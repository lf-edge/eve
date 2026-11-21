// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package objtonum

import (
	"fmt"
	"reflect"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// ObjKey is a key uniquely referencing an object.
type ObjKey interface {
	// Key returns string representation of the key.
	Key() string
}

// ObjKeySelector is function that selects a subset of keys.
// To select a given key it should return true, false otherwise.
type ObjKeySelector func(ObjKey) bool

// AllKeys selects all keys.
var AllKeys ObjKeySelector = func(ObjKey) bool { return true }

// Map maps numbers (integers) to objects (can be anything that can be referenced
// using ObjKey).
type Map interface {
	// Get returns number assigned to the given object.
	Get(ObjKey) (number int, reservedOnly bool, err error)
	// Assign either adds new Object->Number pair into the map or modifies number
	// assigned to the given object.
	// Disallow modification by requesting exclusive assignment.
	// Removes reserved-only flag from the assigned number.
	// Assign also causes update of "lastUpdatedAt" timestamp stored alongside the number.
	Assign(key ObjKey, number int, exclusively bool) error
	// Delete either fully removes Object->Number pair from the map,
	// or just marks the number as only reserved if keepReserved is true.
	Delete(key ObjKey, keepReserved bool) error
	// Iterate over every Object->Number pair stored in the map.
	// It is safe to Delete pair during iteration.
	Iterate(MapIterFunc)
}

// MapIterFunc is a callback applied to every Object->Number pair inside the Map
// during iteration.
// Return stop as true to terminate the iteration.
type MapIterFunc func(key ObjKey, number int, onlyReserved bool,
	createdAt, lastUpdatedAt time.Time) (stop bool)

// PublishedMap implements (potentially persisted) objtonum.Map using a pubsub publication.
type PublishedMap struct {
	log        *base.LogObject
	publisher  *ObjNumPublisher
	usedFor    ObjKeySelector
	numberType string
}

// NewPublishedMap is a constructor for PublishedMap.
// PublishedMap publishes map updates using the provided ObjNumPublisher.
// Multiple PublishedMap can use the same publisher provided that their numberType-s
// are different or, if they publish numbers of the same type, usedFor key selectors
// must select disjoint sets of keys.
func NewPublishedMap(log *base.LogObject, publisher *ObjNumPublisher,
	numberType string, usedFor ObjKeySelector) *PublishedMap {
	return &PublishedMap{
		log:        log,
		publisher:  publisher,
		usedFor:    usedFor,
		numberType: numberType,
	}
}

// Get returns number assigned to the given object.
func (pb *PublishedMap) Get(key ObjKey) (number int, reservedOnly bool, err error) {
	if !pb.usedFor(key) {
		return 0, false, fmt.Errorf(
			"wrong PublishedMap used with ObjKey %s (key mismatch)", key.Key())
	}
	objNum, err := pb.publisher.Get(key)
	if err != nil {
		return 0, false, err
	}
	number, numberType := objNum.GetNumber()
	if numberType != pb.numberType {
		return 0, false, fmt.Errorf(
			"wrong PublishedMap used with ObjKey %s (numberType mismatch)", key.Key())
	}
	return number, objNum.IsReservedOnly(), nil
}

// Assign either adds new Object->Number pair into the map or modifies number
// assigned to the given object.
// Disallow modification by requesting exclusive assignment.
// Removes reserved-only flag from the assigned number.
// Assign also causes update of lastUpdatedAt timestamp stored alongside the number.
func (pb *PublishedMap) Assign(key ObjKey, number int, exclusively bool) error {
	if !pb.usedFor(key) {
		return fmt.Errorf("ObjKey %s used with a wrong PublishedMap", key.Key())
	}
	if objNum, err := pb.publisher.Get(key); err == nil {
		if exclusively {
			return fmt.Errorf("ObjKey %s has already a number assigned", key.Key())
		}
		if _, numberType := objNum.GetNumber(); numberType != pb.numberType {
			return fmt.Errorf(
				"wrong PublishedMap used with ObjKey %s (numberType mismatch)", key.Key())
		}
		objNum.SetNumber(number, pb.numberType)
		objNum.SetReservedOnly(false)
		return pb.publisher.Publish(objNum)
	}
	objNum := pb.publisher.PrepareContainer(key)
	objNum.SetNumber(number, pb.numberType)
	objNum.SetReservedOnly(false)
	return pb.publisher.Publish(objNum)
}

// Delete either fully removes Object->Number pair from the map,
// or just marks the number as only reserved if keepReserved is true.
func (pb *PublishedMap) Delete(key ObjKey, keepReserved bool) error {
	if !pb.usedFor(key) {
		return fmt.Errorf("wrong PublishedMap used with ObjKey %s (key mismatch)", key.Key())
	}
	objNum, err := pb.publisher.Get(key)
	if err != nil {
		return err
	}
	if _, numberType := objNum.GetNumber(); numberType != pb.numberType {
		return fmt.Errorf(
			"wrong PublishedMap used with ObjKey %s (numberType mismatch)", key.Key())
	}
	if keepReserved {
		objNum.SetReservedOnly(true)
		return pb.publisher.Publish(objNum)
	}
	return pb.publisher.Unpublish(objNum.GetKey())
}

// Iterate over every Object->Number pair stored in the map.
func (pb *PublishedMap) Iterate(callback MapIterFunc) {
	for _, objNum := range pb.publisher.GetAll() {
		if !pb.usedFor(objNum.GetKey()) {
			continue
		}
		key := objNum.GetKey()
		number, numberType := objNum.GetNumber()
		if numberType != pb.numberType {
			continue
		}
		createdAt, lastUpdatedAt := objNum.GetTimestamps()
		stop := callback(key, number, objNum.IsReservedOnly(),
			createdAt, lastUpdatedAt)
		if stop {
			return
		}
	}
}

// ObjNumPublisher is used by PublishedMap to publish Object->Number pairs.
type ObjNumPublisher struct {
	log        *base.LogObject
	pub        pubsub.Publication
	objNumCont ObjNumContainer
}

// ObjNumContainer is used by ObjNumPublisher to store and publish number
// assigned to an object.
type ObjNumContainer interface {
	// New is a constructor for the ObjNumContainer.
	// New works even when the method receiver is nil.
	New(ObjKey) ObjNumContainer
	// GetKey returns the key of the object whose number is stored by this container.
	GetKey() ObjKey
	// SetNumber updates the number stored by the container.
	// numberType can give a semantic label to the number. It allows to reuse the same
	// pubsub topic (ObjNumContainer) for multiple semantically different mappings.
	// Additionally, the method updates <lastUpdatedAt> timestamp, which can be obtained
	// using GetTimestamps.
	SetNumber(number int, numberType string)
	// GetNumber returns number stored by the container.
	GetNumber() (number int, numberType string)
	// GetTimestamps returns time when the container was created and also time when
	// the stored number or the reserved flag was last changed.
	GetTimestamps() (createdAt time.Time, lastUpdatedAt time.Time)
	// SetReservedOnly allows to change the reservation status.
	// Number is either fully assigned to the object or just reserved for a potential
	// future assignment to this object.
	SetReservedOnly(reservedOnly bool)
	// IsReservedOnly returns true if the number is only reserved.
	IsReservedOnly() bool
}

// NewObjNumPublisher is a constructor for ObjNumPublisher
func NewObjNumPublisher(log *base.LogObject, ps *pubsub.PubSub, agentName string,
	persisted bool, objNumCont ObjNumContainer) (*ObjNumPublisher, error) {
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		Persistent: persisted,
		TopicType:  dereferenceContainer(objNumCont),
	})
	_ = pub.ClearRestarted()
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return &ObjNumPublisher{
		log:        log,
		pub:        pub,
		objNumCont: objNumCont,
	}, nil
}

// PrepareContainer returns a new container to later store inside and publish
// an assigned object number.
func (p *ObjNumPublisher) PrepareContainer(key ObjKey) ObjNumContainer {
	return p.objNumCont.New(key)
}

// Get returns last published number for the given object or error
// if nothing is currently published under this object key.
func (p *ObjNumPublisher) Get(key ObjKey) (ObjNumContainer, error) {
	objNum, err := p.pub.Get(key.Key())
	if err != nil {
		return nil, err
	}
	return covertToContainer(objNum)
}

// GetAll returns all object numbers currently published inside the pubsub topic.
func (p *ObjNumPublisher) GetAll() []ObjNumContainer {
	publishedNums := p.pub.GetAll()
	allObjNums := make([]ObjNumContainer, 0, len(publishedNums))
	for _, objNum := range publishedNums {
		objNumCont, err := covertToContainer(objNum)
		if err == nil {
			allObjNums = append(allObjNums, objNumCont)
		} else {
			p.log.Error(err)
		}
	}
	return allObjNums
}

// Publish publishes the given object number into the pubsub topic.
func (p *ObjNumPublisher) Publish(objNum ObjNumContainer) error {
	k := objNum.GetKey()
	return p.pub.Publish(k.Key(), dereferenceContainer(objNum))
}

// Unpublish removes number currently published for the given object
// from the pubsub topic.
func (p *ObjNumPublisher) Unpublish(key ObjKey) error {
	return p.pub.Unpublish(key.Key())
}

// Close publisher and the pubsub channel.
func (p *ObjNumPublisher) Close() error {
	return p.pub.Close()
}

func dereferenceContainer(val ObjNumContainer) interface{} {
	reflectVal := reflect.ValueOf(val)
	if reflectVal.Kind() == reflect.Ptr {
		reflectVal = reflectVal.Elem()
	}
	return reflectVal.Interface()
}

func covertToContainer(val interface{}) (ObjNumContainer, error) {
	if cont, ok := val.(ObjNumContainer); ok {
		return cont, nil
	}
	reflectVal := reflect.ValueOf(val)
	reflectPtr := reflect.New(reflectVal.Type())
	reflectPtr.Elem().Set(reflectVal)
	valPtr := reflectPtr.Interface()
	if container, ok := valPtr.(ObjNumContainer); ok {
		return container, nil
	}
	return nil, fmt.Errorf("published value %v does not implement ObjNumContainer", val)
}
