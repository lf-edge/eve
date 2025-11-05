// Copyright (c) 2024-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub_test

import (
	"net"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/onsi/gomega"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

func TestMemoryDriverPubSub(t *testing.T) {
	t.Parallel()
	g := gomega.NewGomegaWithT(t)

	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	drv := pubsub.NewMemoryDriver()
	ps := pubsub.New(drv, logger, log)

	appNetworkStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "zedrouter",
		TopicType: types.AppNetworkStatus{},
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	u, err := uuid.FromString("6ba7b810-9dad-11d1-80b4-000000000000")
	g.Expect(err).ToNot(gomega.HaveOccurred())

	expected := types.AppNetworkStatus{
		UUIDandVersion: types.UUIDandVersion{
			UUID:    u,
			Version: "1.0",
		},
		AppNetAdapterList: []types.AppNetAdapterStatus{
			{
				AssignedAddresses: types.AssignedAddrs{
					IPv4Addrs: []types.AssignedAddr{
						{
							Address:    net.ParseIP("192.168.1.1"),
							AssignedBy: types.AddressSourceInternalDHCP,
						},
					},
				},
			},
		},
	}
	key := "6ba7b810-9dad-11d1-80b4-000000000001"
	err = appNetworkStatus.Publish(key, expected)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	got, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:  "zedrouter",
		TopicImpl:  types.AppNetworkStatus{},
		Persistent: true,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())
	err = got.Activate()
	g.Expect(err).ToNot(gomega.HaveOccurred())

	items := got.GetAll()
	g.Expect(items).To(gomega.HaveLen(1))

	g.Expect(items[key]).To(gomega.BeEquivalentTo(expected))
}

// TestMemoryDriverAsyncNotifications tests that MemoryDriver sends Change notifications
// via MsgChan when Publish/Unpublish is called
func TestMemoryDriverAsyncNotifications(t *testing.T) {
	t.Parallel()
	g := gomega.NewGomegaWithT(t)

	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	drv := pubsub.NewMemoryDriver()
	ps := pubsub.New(drv, logger, log)

	// Create publication
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "test-agent",
		TopicType:  types.AppNetworkStatus{},
		Persistent: false,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Create subscription with handlers
	receivedChanges := make([]pubsub.Change, 0)
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "test-agent",
		TopicImpl: types.AppNetworkStatus{},
		Activate:  false,
		CreateHandler: func(ctxArg interface{}, key string, item interface{}) {
			// Handler called on create
		},
		ModifyHandler: func(ctxArg interface{}, key string, item interface{}, oldItem interface{}) {
			// Handler called on modify
		},
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	err = sub.Activate()
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Start goroutine to receive changes
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 3; i++ { // Expect 3 changes: 2 publishes + 1 unpublish
			select {
			case change := <-sub.MsgChan():
				receivedChanges = append(receivedChanges, change)
				sub.ProcessChange(change)
			}
		}
	}()

	// Publish first item
	u1, _ := uuid.FromString("6ba7b810-9dad-11d1-80b4-000000000001")
	item1 := types.AppNetworkStatus{
		UUIDandVersion: types.UUIDandVersion{
			UUID:    u1,
			Version: "1.0",
		},
	}
	err = pub.Publish("key1", item1)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Publish second item
	u2, _ := uuid.FromString("6ba7b810-9dad-11d1-80b4-000000000002")
	item2 := types.AppNetworkStatus{
		UUIDandVersion: types.UUIDandVersion{
			UUID:    u2,
			Version: "2.0",
		},
	}
	err = pub.Publish("key2", item2)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Unpublish first item
	err = pub.Unpublish("key1")
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Wait for goroutine to receive all changes
	<-done

	// Verify we received 3 changes
	g.Expect(receivedChanges).To(gomega.HaveLen(3))

	// Verify first change is Modify for key1
	g.Expect(receivedChanges[0].Operation).To(gomega.Equal(pubsub.Modify))
	g.Expect(receivedChanges[0].Key).To(gomega.Equal("key1"))
	g.Expect(receivedChanges[0].Value).ToNot(gomega.BeNil())

	// Verify second change is Modify for key2
	g.Expect(receivedChanges[1].Operation).To(gomega.Equal(pubsub.Modify))
	g.Expect(receivedChanges[1].Key).To(gomega.Equal("key2"))
	g.Expect(receivedChanges[1].Value).ToNot(gomega.BeNil())

	// Verify third change is Delete for key1
	g.Expect(receivedChanges[2].Operation).To(gomega.Equal(pubsub.Delete))
	g.Expect(receivedChanges[2].Key).To(gomega.Equal("key1"))

	// Verify items in subscription
	items := sub.GetAll()
	g.Expect(items).To(gomega.HaveLen(1)) // Only key2 remains
	g.Expect(items["key2"]).To(gomega.BeEquivalentTo(item2))
}

// TestMemoryDriverMultipleTopics tests that subscribers on different topics
// only receive notifications for their topic
func TestMemoryDriverMultipleTopics(t *testing.T) {
	t.Parallel()
	g := gomega.NewGomegaWithT(t)

	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	drv := pubsub.NewMemoryDriver()
	ps := pubsub.New(drv, logger, log)

	// Create publications for two different topics
	pubTopic1, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "agent1",
		TopicType:  types.AppNetworkStatus{},
		Persistent: false,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	pubTopic2, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "agent2",
		TopicType:  types.DeviceNetworkStatus{},
		Persistent: false,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Create subscription for topic1
	topic1Changes := make([]pubsub.Change, 0)
	subTopic1, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "agent1",
		TopicImpl: types.AppNetworkStatus{},
		Activate:  true,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Create subscription for topic2
	topic2Changes := make([]pubsub.Change, 0)
	subTopic2, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "agent2",
		TopicImpl: types.DeviceNetworkStatus{},
		Activate:  true,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Start goroutines to receive changes
	done1 := make(chan struct{})
	done2 := make(chan struct{})

	go func() {
		defer close(done1)
		for i := 0; i < 1; i++ {
			change := <-subTopic1.MsgChan()
			topic1Changes = append(topic1Changes, change)
		}
	}()

	go func() {
		defer close(done2)
		for i := 0; i < 1; i++ {
			change := <-subTopic2.MsgChan()
			topic2Changes = append(topic2Changes, change)
		}
	}()

	// Publish to topic1
	u1, _ := uuid.FromString("6ba7b810-9dad-11d1-80b4-000000000001")
	item1 := types.AppNetworkStatus{
		UUIDandVersion: types.UUIDandVersion{UUID: u1, Version: "1.0"},
	}
	err = pubTopic1.Publish("key1", item1)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Publish to topic2
	item2 := types.DeviceNetworkStatus{}
	err = pubTopic2.Publish("key2", item2)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Wait for both subscribers to receive their changes
	<-done1
	<-done2

	// Verify topic1 subscriber only received topic1 change
	g.Expect(topic1Changes).To(gomega.HaveLen(1))
	g.Expect(topic1Changes[0].Key).To(gomega.Equal("key1"))

	// Verify topic2 subscriber only received topic2 change
	g.Expect(topic2Changes).To(gomega.HaveLen(1))
	g.Expect(topic2Changes[0].Key).To(gomega.Equal("key2"))
}

// TestMemoryDriverSubscriberStop tests that subscriber unregisters when Stop() is called
func TestMemoryDriverSubscriberStop(t *testing.T) {
	t.Parallel()
	g := gomega.NewGomegaWithT(t)

	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	drv := pubsub.NewMemoryDriver()
	ps := pubsub.New(drv, logger, log)

	// Create publication
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "test-agent",
		TopicType:  types.AppNetworkStatus{},
		Persistent: false,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Create subscription
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "test-agent",
		TopicImpl: types.AppNetworkStatus{},
		Activate:  true,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Publish item - should be received
	u1, _ := uuid.FromString("6ba7b810-9dad-11d1-80b4-000000000001")
	item1 := types.AppNetworkStatus{
		UUIDandVersion: types.UUIDandVersion{UUID: u1, Version: "1.0"},
	}
	err = pub.Publish("key1", item1)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Receive the change
	select {
	case change := <-sub.MsgChan():
		g.Expect(change.Key).To(gomega.Equal("key1"))
	}

	// Close the subscription
	err = sub.Close()
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Publish another item - should NOT be received
	u2, _ := uuid.FromString("6ba7b810-9dad-11d1-80b4-000000000002")
	item2 := types.AppNetworkStatus{
		UUIDandVersion: types.UUIDandVersion{UUID: u2, Version: "2.0"},
	}
	err = pub.Publish("key2", item2)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Verify no change is received (channel should not have any messages)
	select {
	case <-sub.MsgChan():
		t.Fatal("Should not receive change after Close()")
	default:
		// Expected - no message received
	}
}

// TestMemoryDriverChangeValueField tests that Change.Value contains the actual data
func TestMemoryDriverChangeValueField(t *testing.T) {
	t.Parallel()
	g := gomega.NewGomegaWithT(t)

	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	drv := pubsub.NewMemoryDriver()
	ps := pubsub.New(drv, logger, log)

	// Create publication
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "test-agent",
		TopicType:  types.AppNetworkStatus{},
		Persistent: false,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Create subscription
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "test-agent",
		TopicImpl: types.AppNetworkStatus{},
		Activate:  true,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Publish item
	u, _ := uuid.FromString("6ba7b810-9dad-11d1-80b4-000000000001")
	expected := types.AppNetworkStatus{
		UUIDandVersion: types.UUIDandVersion{
			UUID:    u,
			Version: "1.0",
		},
		AppNetAdapterList: []types.AppNetAdapterStatus{
			{
				AssignedAddresses: types.AssignedAddrs{
					IPv4Addrs: []types.AssignedAddr{
						{
							Address:    net.ParseIP("192.168.1.1"),
							AssignedBy: types.AddressSourceInternalDHCP,
						},
					},
				},
			},
		},
	}
	err = pub.Publish("key1", expected)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// Receive the change
	change := <-sub.MsgChan()

	// Verify Change has Operation, Key, and Value populated
	g.Expect(change.Operation).To(gomega.Equal(pubsub.Modify))
	g.Expect(change.Key).To(gomega.Equal("key1"))
	g.Expect(change.Value).ToNot(gomega.BeNil())
	g.Expect(len(change.Value)).To(gomega.BeNumerically(">", 0))

	// Process the change and verify the item is correct
	sub.ProcessChange(change)
	items := sub.GetAll()
	g.Expect(items).To(gomega.HaveLen(1))
	g.Expect(items["key1"]).To(gomega.BeEquivalentTo(expected))
}
