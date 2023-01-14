// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package objtonum_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/objtonum"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

func TestAllocator(test *testing.T) {
	test.Parallel()
	t := NewWithT(test)
	logger := logrus.StandardLogger()
	logObj := base.NewSourceLogObject(logger, "test", 1234)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, logObj)

	publisher, err := objtonum.NewObjNumPublisher(
		logObj, ps, "test-agent", false, &TestObjNumContainer{})
	t.Expect(err).ToNot(HaveOccurred())

	usedFor := objtonum.AllKeys
	pubMap := objtonum.NewPublishedMap(logObj, publisher, numType1, usedFor)

	withZeroVal := false
	numAlloc := objtonum.NewByteAllocator(withZeroVal)

	allocator, err := objtonum.NewAllocator(logObj, numAlloc, pubMap)
	t.Expect(err).ToNot(HaveOccurred())

	allocatedCount, reservedCount := allocator.AllocatedCount()
	t.Expect(allocatedCount).To(BeZero())
	t.Expect(reservedCount).To(BeZero())

	// Allocate number for one object.
	key := TestObjKey{ObjName: "my-obj", ObjType: objType1}
	num, err := allocator.GetOrAllocate(key, objtonum.LowestFree)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(BeNumerically(">", 0))
	t.Expect(num).To(BeNumerically("<", 256))
	sameNum, err := allocator.GetOrAllocate(key)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(sameNum).To(Equal(num))
	allocatedCount, reservedCount = allocator.AllocatedCount()
	t.Expect(allocatedCount).To(Equal(1))
	t.Expect(reservedCount).To(BeZero())

	// Mark the allocated number as reserved only.
	err = allocator.Free(key, true)
	t.Expect(err).ToNot(HaveOccurred())
	allocatedCount, reservedCount = allocator.AllocatedCount()
	t.Expect(allocatedCount).To(BeZero())
	t.Expect(reservedCount).To(Equal(1))

	// Re-allocate the reserved number.
	sameNum, err = allocator.GetOrAllocate(key)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(sameNum).To(Equal(num))
	allocatedCount, reservedCount = allocator.AllocatedCount()
	t.Expect(allocatedCount).To(Equal(1))
	t.Expect(reservedCount).To(BeZero())

	// Free the number completely.
	err = allocator.Free(key, false)
	t.Expect(err).ToNot(HaveOccurred())
	allocatedCount, reservedCount = allocator.AllocatedCount()
	t.Expect(allocatedCount).To(BeZero())
	t.Expect(reservedCount).To(BeZero())

	// Allocate all available numbers.
	allocated := make(map[int]struct{})
	for i := 1; i < 256; i++ {
		key = TestObjKey{
			ObjName: fmt.Sprintf("my-obj%d", i),
			ObjType: objType1,
		}
		num, err := allocator.GetOrAllocate(key)
		t.Expect(err).ToNot(HaveOccurred())
		_, duplicate := allocated[num]
		t.Expect(duplicate).To(BeFalse())
		allocated[num] = struct{}{}
	}
	allocatedCount, reservedCount = allocator.AllocatedCount()
	t.Expect(allocatedCount).To(Equal(255))
	t.Expect(reservedCount).To(BeZero())

	// Try to allocate one more - should fail.
	key = TestObjKey{ObjName: "my-obj256", ObjType: objType1}
	_, err = allocator.GetOrAllocate(key)
	t.Expect(err).To(HaveOccurred())

	// Mark all as reservation.
	err = allocator.FreeMultiple(objtonum.AllKeys, true)
	t.Expect(err).ToNot(HaveOccurred())
	allocatedCount, reservedCount = allocator.AllocatedCount()
	t.Expect(allocatedCount).To(BeZero())
	t.Expect(reservedCount).To(Equal(255))

	// Free all completely.
	err = allocator.FreeMultiple(objtonum.AllKeys, false)
	t.Expect(err).ToNot(HaveOccurred())
	allocatedCount, reservedCount = allocator.AllocatedCount()
	t.Expect(allocatedCount).To(BeZero())
	t.Expect(reservedCount).To(BeZero())
}

func TestAllocatorGC(test *testing.T) {
	test.Parallel()
	t := NewWithT(test)
	logger := logrus.StandardLogger()
	logObj := base.NewSourceLogObject(logger, "test", 1234)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, logObj)

	publisher, err := objtonum.NewObjNumPublisher(
		logObj, ps, "test-agent", false, &TestObjNumContainer{})
	t.Expect(err).ToNot(HaveOccurred())

	usedFor := objtonum.AllKeys
	pubMap := objtonum.NewPublishedMap(logObj, publisher, numType1, usedFor)

	withZeroVal := false
	numAlloc := objtonum.NewByteAllocator(withZeroVal)

	allocator, err := objtonum.NewAllocator(logObj, numAlloc, pubMap)
	t.Expect(err).ToNot(HaveOccurred())

	// Allocate numbers for 100 objects.
	for i := 1; i <= 100; i++ {
		key := TestObjKey{
			ObjName: fmt.Sprintf("my-obj%d", i),
			ObjType: objType1,
		}
		_, err = allocator.GetOrAllocate(key)
		t.Expect(err).ToNot(HaveOccurred())
	}
	allocatedCount, reservedCount := allocator.AllocatedCount()
	t.Expect(allocatedCount).To(Equal(100))
	t.Expect(reservedCount).To(BeZero())

	// GC will clean only those (in future reserved) numbers that were allocated so far.
	cleanBefore := time.Now()

	// Mark all numbers as reserved-only.
	err = allocator.FreeMultiple(objtonum.AllKeys, true)
	t.Expect(err).ToNot(HaveOccurred())
	allocatedCount, reservedCount = allocator.AllocatedCount()
	t.Expect(allocatedCount).To(BeZero())
	t.Expect(reservedCount).To(Equal(100))

	// (Re)allocate number for every second object.
	for i := 1; i <= 100; i++ {
		if i%2 == 1 {
			continue
		}
		key := TestObjKey{
			ObjName: fmt.Sprintf("my-obj%d", i),
			ObjType: objType1,
		}
		_, err = allocator.GetOrAllocate(key)
		t.Expect(err).ToNot(HaveOccurred())
	}
	allocatedCount, reservedCount = allocator.AllocatedCount()
	t.Expect(allocatedCount).To(Equal(50))
	t.Expect(reservedCount).To(Equal(50))

	// Allocate numbers for another 100 objects.
	var objType string
	for i := 101; i <= 200; i++ {
		objType = objType2
		if i%2 == 0 {
			objType = objType3
		}
		key := TestObjKey{
			ObjName: fmt.Sprintf("my-obj%d", i),
			ObjType: objType,
		}
		_, err = allocator.GetOrAllocate(key)
		t.Expect(err).ToNot(HaveOccurred())
	}
	allocatedCount, reservedCount = allocator.AllocatedCount()
	t.Expect(allocatedCount).To(Equal(150))
	t.Expect(reservedCount).To(Equal(50))

	// Mark half of these new 100 allocations as reserved-only.
	err = allocator.FreeMultiple(func(objKey objtonum.ObjKey) bool {
		key, ok := objKey.(TestObjKey)
		t.Expect(ok).To(BeTrue())
		return key.ObjType == objType2
	}, true)
	t.Expect(err).ToNot(HaveOccurred())
	allocatedCount, reservedCount = allocator.AllocatedCount()
	t.Expect(allocatedCount).To(Equal(100))
	t.Expect(reservedCount).To(Equal(100))

	// GC reserved numbers created in the first for-cycle.
	err = allocator.GC(cleanBefore)
	t.Expect(err).ToNot(HaveOccurred())
	allocatedCount, reservedCount = allocator.AllocatedCount()
	t.Expect(allocatedCount).To(Equal(100))
	t.Expect(reservedCount).To(Equal(50))

	// Check what was preserved using Free.
	for i := 1; i <= 200; i++ {
		shouldExist := true
		if i%2 == 1 && i <= 100 {
			shouldExist = false
		}
		objType = objType1
		if i > 100 {
			objType = objType2
			if i%2 == 0 {
				objType = objType3
			}
		}
		key := TestObjKey{
			ObjName: fmt.Sprintf("my-obj%d", i),
			ObjType: objType,
		}
		err := allocator.Free(key, false)
		if shouldExist {
			t.Expect(err).ToNot(HaveOccurred())
		} else {
			t.Expect(err).To(HaveOccurred())
		}
	}
}

func TestAllocStrategies(test *testing.T) {
	test.Parallel()
	t := NewWithT(test)
	logger := logrus.StandardLogger()
	logObj := base.NewSourceLogObject(logger, "test", 1234)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, logObj)

	publisher, err := objtonum.NewObjNumPublisher(
		logObj, ps, "test-agent", false, &TestObjNumContainer{})
	t.Expect(err).ToNot(HaveOccurred())

	usedFor := objtonum.AllKeys
	pubMap := objtonum.NewPublishedMap(logObj, publisher, numType1, usedFor)

	withZeroVal := true
	numAlloc := objtonum.NewByteAllocator(withZeroVal)

	allocator, err := objtonum.NewAllocator(logObj, numAlloc, pubMap)
	t.Expect(err).ToNot(HaveOccurred())

	key := TestObjKey{ObjName: "my-obj1", ObjType: objType1}
	num, err := allocator.GetOrAllocate(key, objtonum.LowestFree)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(Equal(0))
	key = TestObjKey{ObjName: "my-obj2", ObjType: objType1}
	num, err = allocator.GetOrAllocate(key, objtonum.LowestFree)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(Equal(1))
	key = TestObjKey{ObjName: "my-obj3", ObjType: objType1}
	num, err = allocator.GetOrAllocate(key, objtonum.HighestFree)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(Equal(255))
	key = TestObjKey{ObjName: "my-obj4", ObjType: objType1}
	num, err = allocator.GetOrAllocate(key, objtonum.HighestFree)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(Equal(254))
	key = TestObjKey{ObjName: "my-obj5", ObjType: objType1}
	num, err = allocator.GetOrAllocate(key, objtonum.RandomFree)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(BeNumerically(">", 1))
	t.Expect(num).To(BeNumerically("<", 254))
}

func TestAllocatorRestart(test *testing.T) {
	test.Parallel()
	t := NewWithT(test)
	logger := logrus.StandardLogger()
	logObj := base.NewSourceLogObject(logger, "test", 1234)

	// Init persistent pubsub topic.
	persistStatusDir, err := os.MkdirTemp("", "TestAllocatorRestart")
	t.Expect(err).ToNot(HaveOccurred())
	defer os.RemoveAll(persistStatusDir)
	ps := pubsub.New(
		&socketdriver.SocketDriver{
			Logger:  logger,
			Log:     logObj,
			RootDir: persistStatusDir,
		},
		logger, logObj)

	publisher, err := objtonum.NewObjNumPublisher(
		logObj, ps, "test-agent", true, &TestObjNumContainer{})
	t.Expect(err).ToNot(HaveOccurred())

	usedFor := objtonum.AllKeys
	pubMap := objtonum.NewPublishedMap(logObj, publisher, numType1, usedFor)

	withZeroVal := false
	numAlloc := objtonum.NewByteAllocator(withZeroVal)

	allocator, err := objtonum.NewAllocator(logObj, numAlloc, pubMap)
	t.Expect(err).ToNot(HaveOccurred())

	// Allocate numbers for 100 objects.
	for i := 1; i <= 100; i++ {
		objType := objType1
		if i%2 == 0 {
			objType = objType2
		}
		key := TestObjKey{
			ObjName: fmt.Sprintf("my-obj%d", i),
			ObjType: objType,
		}
		_, err = allocator.GetOrAllocate(key)
		t.Expect(err).ToNot(HaveOccurred())
	}
	allocatedCount, reservedCount := allocator.AllocatedCount()
	t.Expect(allocatedCount).To(Equal(100))
	t.Expect(reservedCount).To(BeZero())

	// Simulate restart.
	err = publisher.Close()
	t.Expect(err).ToNot(HaveOccurred())
	publisher, err = objtonum.NewObjNumPublisher(
		logObj, ps, "test-agent", true, &TestObjNumContainer{})
	t.Expect(err).ToNot(HaveOccurred())
	// Also, with re-created map accept only half of the keys (just to test usedFor).
	usedFor = func(objKey objtonum.ObjKey) bool {
		key, ok := objKey.(TestObjKey)
		t.Expect(ok).To(BeTrue())
		return key.ObjType == objType1
	}
	pubMap = objtonum.NewPublishedMap(logObj, publisher, numType1, usedFor)
	numAlloc = objtonum.NewByteAllocator(withZeroVal)
	allocator, err = objtonum.NewAllocator(logObj, numAlloc, pubMap)
	t.Expect(err).ToNot(HaveOccurred())
	allocatedCount, reservedCount = allocator.AllocatedCount()
	t.Expect(allocatedCount).To(Equal(50))
	t.Expect(reservedCount).To(BeZero())
	key := TestObjKey{ObjName: "my-obj1", ObjType: objType1}
	num, err := allocator.GetOrAllocate(key)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(Equal(1))
	key = TestObjKey{ObjName: "my-obj2", ObjType: objType2}
	_, err = allocator.GetOrAllocate(key)
	t.Expect(err).To(HaveOccurred())

	// Only 205 numbers are now left free for allocation.
	for i := 101; i <= 305; i++ {
		key := TestObjKey{
			ObjName: fmt.Sprintf("my-obj%d", i),
			ObjType: objType1,
		}
		_, err = allocator.GetOrAllocate(key)
		t.Expect(err).ToNot(HaveOccurred())
	}
	_, err = allocator.GetOrAllocate(key)
	t.Expect(err).To(HaveOccurred())
}

func TestReusedOldestReserved(test *testing.T) {
	test.Parallel()
	t := NewWithT(test)
	logger := logrus.StandardLogger()
	logObj := base.NewSourceLogObject(logger, "test", 1234)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, logObj)

	publisher, err := objtonum.NewObjNumPublisher(
		logObj, ps, "test-agent", false, &TestObjNumContainer{})
	t.Expect(err).ToNot(HaveOccurred())

	usedFor := objtonum.AllKeys
	pubMap := objtonum.NewPublishedMap(logObj, publisher, numType1, usedFor)

	withZeroVal := false
	numAlloc := objtonum.NewByteAllocator(withZeroVal)

	allocator, err := objtonum.NewAllocator(logObj, numAlloc, pubMap)
	t.Expect(err).ToNot(HaveOccurred())

	// Allocate all available numbers.
	for i := 1; i < 256; i++ {
		key := TestObjKey{
			ObjName: fmt.Sprintf("my-obj%d", i),
			ObjType: objType1,
		}
		_, err := allocator.GetOrAllocate(key)
		t.Expect(err).ToNot(HaveOccurred())
	}
	allocatedCount, reservedCount := allocator.AllocatedCount()
	t.Expect(allocatedCount).To(Equal(255))
	t.Expect(reservedCount).To(BeZero())

	// Mark some numbers as reserved-only.
	key := TestObjKey{ObjName: "my-obj42", ObjType: objType1}
	err = allocator.Free(key, true)
	t.Expect(err).ToNot(HaveOccurred())
	key = TestObjKey{ObjName: "my-obj13", ObjType: objType1}
	err = allocator.Free(key, true)
	t.Expect(err).ToNot(HaveOccurred())
	key = TestObjKey{ObjName: "my-obj109", ObjType: objType1}
	err = allocator.Free(key, true)
	t.Expect(err).ToNot(HaveOccurred())
	key = TestObjKey{ObjName: "my-obj201", ObjType: objType1}
	err = allocator.Free(key, true)
	t.Expect(err).ToNot(HaveOccurred())

	// Next allocations will steal reserved numbers.
	key = TestObjKey{ObjName: "my-obj256", ObjType: objType1}
	num, err := allocator.GetOrAllocate(key)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(Equal(42)) // oldest reserved
	key = TestObjKey{ObjName: "my-obj257", ObjType: objType1}
	num, err = allocator.GetOrAllocate(key)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(Equal(13)) // second oldest reserved
	key = TestObjKey{ObjName: "my-obj258", ObjType: objType1}
	num, err = allocator.GetOrAllocate(key)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(Equal(109))
	key = TestObjKey{ObjName: "my-obj259", ObjType: objType1}
	num, err = allocator.GetOrAllocate(key)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(num).To(Equal(201))

	// Nothing reserved to steal anymore.
	key = TestObjKey{ObjName: "my-obj260", ObjType: objType1}
	_, err = allocator.GetOrAllocate(key)
	t.Expect(err).To(HaveOccurred())
}
