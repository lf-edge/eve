// Copyright (c) 2024 Zededa, Inc.
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
				AllocatedIPv4Addr: net.ParseIP("192.168.1.1"),
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
