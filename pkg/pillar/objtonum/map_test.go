// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package objtonum_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/objtonum"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

const (
	objType1 = "obj-type1"
	objType2 = "obj-type2"
	objType3 = "obj-type3"
	numType1 = "num-type1"
)

type TestObjKey struct {
	ObjName string
	ObjType string
}

func (k TestObjKey) Key() string {
	return fmt.Sprintf("%s-%s", k.ObjType, k.ObjName)
}

type TestObjNumContainer struct {
	TestObjKey
	CreatedAt     time.Time
	LastUpdatedAt time.Time
	Number        int
	NumberType    string
	ReservedOnly  bool
}

func (c *TestObjNumContainer) New(objKey objtonum.ObjKey) objtonum.ObjNumContainer {
	key, ok := objKey.(TestObjKey)
	if !ok {
		panic("objKey is not TestObjKey")
	}
	return &TestObjNumContainer{
		TestObjKey:    key,
		CreatedAt:     time.Now(),
		LastUpdatedAt: time.Now(),
	}
}

func (c *TestObjNumContainer) GetKey() objtonum.ObjKey {
	return c.TestObjKey
}

func (c *TestObjNumContainer) SetNumber(number int, numberType string) {
	c.Number = number
	c.NumberType = numberType
	c.LastUpdatedAt = time.Now()
}

func (c *TestObjNumContainer) GetNumber() (number int, numberType string) {
	return c.Number, c.NumberType
}

func (c *TestObjNumContainer) GetTimestamps() (createdAt time.Time, lastUpdatedAt time.Time) {
	return c.CreatedAt, c.LastUpdatedAt
}

func (c *TestObjNumContainer) SetReservedOnly(reservedOnly bool) {
	c.ReservedOnly = reservedOnly
	c.LastUpdatedAt = time.Now()
}

func (c *TestObjNumContainer) IsReservedOnly() bool {
	return c.ReservedOnly
}

func getMapLength(m objtonum.Map) int {
	var length int
	m.Iterate(func(_ objtonum.ObjKey, _ int, _ bool, _, _ time.Time) (stop bool) {
		length++
		return
	})
	return length
}

func TestPublishedMap(test *testing.T) {
	test.Parallel()
	t := NewWithT(test)
	logger := logrus.StandardLogger()
	logObj := base.NewSourceLogObject(logger, "test", 1234)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, logObj)

	publisher, err := objtonum.NewObjNumPublisher(
		logObj, ps, "test-agent", false, &TestObjNumContainer{})
	t.Expect(err).ToNot(HaveOccurred())

	usedFor := objtonum.AllKeys
	pubMap := objtonum.NewPublishedMap(logObj, publisher, "num-type1", usedFor)

	// Initially the map is empty.
	t.Expect(getMapLength(pubMap)).To(BeZero())
	key := TestObjKey{ObjName: "my-obj", ObjType: objType1}
	_, _, err = pubMap.Get(key)
	t.Expect(err).To(HaveOccurred())
	err = pubMap.Delete(key, false)
	t.Expect(err).To(HaveOccurred())

	// Add single item.
	number := 10
	beforeFirstAssign := time.Now()
	err = pubMap.Assign(key, number, true)
	afterFirstAssign := time.Now()
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(getMapLength(pubMap)).To(Equal(1))
	num, reservedOnly, err := pubMap.Get(key)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(Equal(number))
	t.Expect(reservedOnly).To(BeFalse())
	pubMap.Iterate(
		func(objKey objtonum.ObjKey, num int, reservedOnly bool,
			createdAt, lastUpdatedAt time.Time) (stop bool) {
			key, ok := objKey.(TestObjKey)
			t.Expect(ok).To(BeTrue())
			t.Expect(key.ObjName).To(Equal(key.ObjName))
			t.Expect(key.ObjType).To(Equal(key.ObjType))
			t.Expect(num).To(Equal(number))
			t.Expect(reservedOnly).To(BeFalse())
			t.Expect(createdAt.After(beforeFirstAssign)).To(BeTrue())
			t.Expect(createdAt.Before(afterFirstAssign)).To(BeTrue())
			t.Expect(lastUpdatedAt.After(beforeFirstAssign)).To(BeTrue())
			t.Expect(lastUpdatedAt.Before(afterFirstAssign)).To(BeTrue())
			return
		})

	// Try to re-add the item
	err = pubMap.Assign(key, number, true)
	t.Expect(err).To(HaveOccurred()) // cannot add exclusively
	err = pubMap.Assign(key, number, false)
	t.Expect(err).ToNot(HaveOccurred()) // can re-add non-exclusively
	afterSecondAssign := time.Now()
	pubMap.Iterate(
		func(k objtonum.ObjKey, num int, reservedOnly bool,
			createdAt, lastUpdatedAt time.Time) (stop bool) {
			t.Expect(num).To(Equal(number))
			t.Expect(reservedOnly).To(BeFalse())
			t.Expect(createdAt.After(beforeFirstAssign)).To(BeTrue())
			t.Expect(createdAt.Before(afterFirstAssign)).To(BeTrue())
			t.Expect(lastUpdatedAt.After(afterFirstAssign)).To(BeTrue())
			t.Expect(lastUpdatedAt.Before(afterSecondAssign)).To(BeTrue())
			return
		})

	// Mark the item as reserved-only.
	err = pubMap.Delete(key, true)
	afterFirstDelete := time.Now()
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(getMapLength(pubMap)).To(Equal(1))
	num, reservedOnly, err = pubMap.Get(key)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(Equal(number))
	t.Expect(reservedOnly).To(BeTrue())
	pubMap.Iterate(
		func(k objtonum.ObjKey, num int, reservedOnly bool,
			createdAt, lastUpdatedAt time.Time) (stop bool) {
			t.Expect(num).To(Equal(number))
			t.Expect(reservedOnly).To(BeTrue())
			t.Expect(createdAt.After(beforeFirstAssign)).To(BeTrue())
			t.Expect(createdAt.Before(afterFirstAssign)).To(BeTrue())
			t.Expect(lastUpdatedAt.After(afterSecondAssign)).To(BeTrue())
			t.Expect(lastUpdatedAt.Before(afterFirstDelete)).To(BeTrue())
			return
		})

	// Remove the item.
	err = pubMap.Delete(key, false)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(getMapLength(pubMap)).To(BeZero())
	_, _, err = pubMap.Get(key)
	t.Expect(err).To(HaveOccurred())

	// Try multiple items.
	number1 := 10
	number2 := 5
	number3 := 30
	key1 := TestObjKey{ObjName: "my-obj1", ObjType: objType1}
	key2 := TestObjKey{ObjName: "my-obj2", ObjType: objType1}
	key3 := TestObjKey{ObjName: "my-obj3", ObjType: objType2}
	usedFor = func(objKey objtonum.ObjKey) bool {
		key, ok := objKey.(TestObjKey)
		t.Expect(ok).To(BeTrue())
		// key3 is not for this map
		return key.ObjType == objType1
	}
	pubMap = objtonum.NewPublishedMap(logObj, publisher, "num-type1", usedFor)
	err = pubMap.Assign(key1, number1, true)
	t.Expect(err).ToNot(HaveOccurred())
	err = pubMap.Assign(key2, number2, true)
	t.Expect(err).ToNot(HaveOccurred())
	err = pubMap.Assign(key3, number3, true) // fails by key selector check
	t.Expect(err).To(HaveOccurred())
	t.Expect(getMapLength(pubMap)).To(Equal(2))
	num, reservedOnly, err = pubMap.Get(key1)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(Equal(number1))
	t.Expect(reservedOnly).To(BeFalse())
	num, reservedOnly, err = pubMap.Get(key2)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(Equal(number2))
	t.Expect(reservedOnly).To(BeFalse())
	_, _, err = pubMap.Get(key3)
	t.Expect(err).To(HaveOccurred())

	// Remove one item, keep the other one.
	err = pubMap.Delete(key1, false)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(getMapLength(pubMap)).To(Equal(1))
	_, _, err = pubMap.Get(key1)
	t.Expect(err).To(HaveOccurred())
	num, reservedOnly, err = pubMap.Get(key2)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(Equal(number2))
	t.Expect(reservedOnly).To(BeFalse())
	_, _, err = pubMap.Get(key3)
	t.Expect(err).To(HaveOccurred())
}

func TestMultipleMapsSinglePublisher(test *testing.T) {
	test.Parallel()
	t := NewWithT(test)
	logger := logrus.StandardLogger()
	logObj := base.NewSourceLogObject(logger, "test", 1234)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, logObj)

	publisher, err := objtonum.NewObjNumPublisher(
		logObj, ps, "test-agent", false, &TestObjNumContainer{})
	t.Expect(err).ToNot(HaveOccurred())

	// Create 3 maps for the same publisher.
	usedFor1 := func(objKey objtonum.ObjKey) bool {
		key, ok := objKey.(TestObjKey)
		t.Expect(ok).To(BeTrue())
		return key.ObjType == objType1
	}
	pubMap1 := objtonum.NewPublishedMap(logObj, publisher, "num-type1", usedFor1)
	usedFor2 := func(objKey objtonum.ObjKey) bool {
		key, ok := objKey.(TestObjKey)
		t.Expect(ok).To(BeTrue())
		return key.ObjType == objType2
	}
	pubMap2 := objtonum.NewPublishedMap(logObj, publisher, "num-type1", usedFor2)
	pubMap3 := objtonum.NewPublishedMap(logObj, publisher, "num-type2", objtonum.AllKeys)

	// Publish via pubMap1.
	key := TestObjKey{ObjName: "my-obj1", ObjType: objType1}
	number := 10
	err = pubMap1.Assign(key, number, true)
	t.Expect(err).ToNot(HaveOccurred())
	_, _, err = pubMap1.Get(key)
	t.Expect(err).ToNot(HaveOccurred())
	_, _, err = pubMap2.Get(key)
	t.Expect(err).To(HaveOccurred())
	_, _, err = pubMap3.Get(key)
	t.Expect(err).To(HaveOccurred())
	key = TestObjKey{ObjName: "my-obj2", ObjType: objType1}
	number = 20
	err = pubMap1.Assign(key, number, true)
	t.Expect(err).ToNot(HaveOccurred())
	_, _, err = pubMap1.Get(key)
	t.Expect(err).ToNot(HaveOccurred())
	_, _, err = pubMap2.Get(key)
	t.Expect(err).To(HaveOccurred())
	_, _, err = pubMap3.Get(key)
	t.Expect(err).To(HaveOccurred())
	t.Expect(getMapLength(pubMap1)).To(Equal(2))
	t.Expect(getMapLength(pubMap2)).To(BeZero())
	t.Expect(getMapLength(pubMap3)).To(BeZero())

	// Publish via pubMap2.
	key = TestObjKey{ObjName: "my-obj1", ObjType: objType2}
	number = 5
	err = pubMap2.Assign(key, number, true)
	t.Expect(err).ToNot(HaveOccurred())
	_, _, err = pubMap1.Get(key)
	t.Expect(err).To(HaveOccurred())
	_, _, err = pubMap2.Get(key)
	t.Expect(err).ToNot(HaveOccurred())
	_, _, err = pubMap3.Get(key)
	t.Expect(err).To(HaveOccurred())
	t.Expect(getMapLength(pubMap1)).To(Equal(2))
	t.Expect(getMapLength(pubMap2)).To(Equal(1))
	t.Expect(getMapLength(pubMap3)).To(BeZero())

	// Publish via pubMap3.
	key = TestObjKey{ObjName: "my-obj1", ObjType: objType1}
	number = 5
	err = pubMap3.Assign(key, number, false)
	t.Expect(err).To(HaveOccurred()) // already assigned and with different type
	key = TestObjKey{ObjName: "my-obj3", ObjType: objType1}
	number = 15
	err = pubMap3.Assign(key, number, true)
	t.Expect(err).ToNot(HaveOccurred())
	_, _, err = pubMap1.Get(key)
	t.Expect(err).To(HaveOccurred())
	_, _, err = pubMap2.Get(key)
	t.Expect(err).To(HaveOccurred())
	_, _, err = pubMap3.Get(key)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(getMapLength(pubMap1)).To(Equal(2))
	t.Expect(getMapLength(pubMap2)).To(Equal(1))
	t.Expect(getMapLength(pubMap3)).To(Equal(1))
}
