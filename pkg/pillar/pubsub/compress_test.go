// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

// TestLargeDevicePortConfigList publishes a DevicePortConfigList far above
// the message size: 30 port configurations of 24 ports each, every port with
// a chain of three proxy CA certificates and two of them with a 300KB PAC
// script, the way nim keeps them while it verifies new configurations. Each
// port repeats its network's proxy configuration, so the list is large and
// compresses into a single message. nim's publication is persistent; this
// one is not, so that the subscriber gets the list over the socket and not
// from the checkpoint.
func TestLargeDevicePortConfigList(t *testing.T) {
	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.ErrorLevel)
	log := base.NewSourceLogObject(logger, "test", 1234)
	ps := pubsub.New(&socketdriver.SocketDriver{Logger: logger, Log: log, RootDir: t.TempDir()},
		logger, log)

	var chain [][]byte
	for i := 0; i < 3; i++ {
		der := make([]byte, 1400)
		_, _ = rand.Read(der)
		chain = append(chain, []byte("-----BEGIN CERTIFICATE-----\n"+
			base64.StdEncoding.EncodeToString(der)+"\n-----END CERTIFICATE-----\n"))
	}
	var pac strings.Builder
	pac.WriteString("function FindProxyForURL(url, host) {\n")
	for i := 0; pac.Len() < 300*1024; i++ {
		fmt.Fprintf(&pac, "  if (shExpMatch(host, \"*.site%05d.corp.example.com\")) "+
			"{ return \"PROXY 10.%d.%d.1:3128\"; }\n", i, i%256, i/256%256)
	}
	pac.WriteString("  return \"DIRECT\";\n}\n")
	pacfile := base64.StdEncoding.EncodeToString([]byte(pac.String()))

	var dpcl types.DevicePortConfigList
	for d := 0; d < 30; d++ {
		dpc := types.DevicePortConfig{
			Version:      types.DPCIsMgmt,
			Key:          "zedagent",
			TimePriority: time.Unix(int64(1700000000+d), 0).UTC(),
		}
		for p := 0; p < 24; p++ {
			port := types.NetworkPortConfig{
				IfName:       fmt.Sprintf("eth%d", p),
				Phylabel:     fmt.Sprintf("eth%d", p),
				Logicallabel: fmt.Sprintf("port%d", p),
				IsMgmt:       p < 2,
				Cost:         uint8(p % 3),
			}
			port.Dhcp = types.DhcpTypeClient
			port.ProxyCertPEM = chain
			if p < 2 {
				port.Pacfile = pacfile
			}
			dpc.Ports = append(dpc.Ports, port)
		}
		dpcl.PortConfigList = append(dpcl.PortConfigList, dpc)
	}
	want, err := json.Marshal(dpcl)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "testnim", TopicType: types.DevicePortConfigList{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Publish("global", dpcl); err != nil {
		t.Fatalf("Publish of a %d byte DevicePortConfigList: %v", len(want), err)
	}
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "testnim", TopicImpl: types.DevicePortConfigList{},
		Activate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.After(60 * time.Second)
	for {
		if item, err := sub.Get("global"); err == nil {
			got, _ := json.Marshal(item)
			if !bytes.Equal(got, want) {
				t.Fatalf("received %d bytes, published %d", len(got), len(want))
			}
			break
		}
		select {
		case change := <-sub.MsgChan():
			sub.ProcessChange(change)
		case <-deadline:
			t.Fatal("timed out waiting for the DevicePortConfigList")
		}
	}
	stats := pubsub.PublicationStats("testnim/DevicePortConfigList")
	t.Logf("DevicePortConfigList of %d bytes sent as %d compressed bytes",
		len(want), stats.CompressedBytes.Load())
	if stats.CompressedMessages.Load() == 0 ||
		pubsub.SubscriptionStats("testnim/DevicePortConfigList").CompressedFrames.Load() == 0 {
		t.Error("the DevicePortConfigList was not sent compressed")
	}
}

type bigItem struct {
	Text string
}

// TestCompressedOnce checks that a value above the frame size is compressed
// once when it is published, and that frame is what every subscriber gets.
func TestCompressedOnce(t *testing.T) {
	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.ErrorLevel)
	log := base.NewSourceLogObject(logger, "test", 1234)
	ps := pubsub.New(&socketdriver.SocketDriver{Logger: logger, Log: log, RootDir: t.TempDir()},
		logger, log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "testonce", TopicType: bigItem{},
	})
	if err != nil {
		t.Fatal(err)
	}
	stats := pubsub.PublicationStats("testonce/bigItem")
	compressions, compressed := stats.Compressions.Load(), stats.CompressedMessages.Load()
	const nsubs = 3
	received := make(chan string, nsubs)
	for i := 0; i < nsubs; i++ {
		sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
			AgentName: "testonce", TopicImpl: bigItem{}, Activate: true,
			CreateHandler: func(_ interface{}, _ string, item interface{}) {
				received <- item.(bigItem).Text
			},
			ModifyHandler: func(_ interface{}, _ string, item, _ interface{}) {
				received <- item.(bigItem).Text
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for change := range sub.MsgChan() {
				sub.ProcessChange(change)
			}
		}()
		defer sub.Close()
	}
	for round := 1; round <= 2; round++ {
		text := strings.Repeat(fmt.Sprintf("round %d of a large value. ", round), 100000)
		if err := pub.Publish("key", bigItem{Text: text}); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < nsubs; i++ {
			select {
			case got := <-received:
				if got != text {
					t.Fatalf("round %d: received %d bytes, published %d", round, len(got), len(text))
				}
			case <-time.After(30 * time.Second):
				t.Fatalf("round %d: %d of %d subscribers received the value", round, i, nsubs)
			}
		}
		if n := stats.Compressions.Load() - compressions; n != int64(round) {
			t.Errorf("round %d: compressed %d times", round, n)
		}
		if n := stats.CompressedMessages.Load() - compressed; n != int64(round*nsubs) {
			t.Errorf("round %d: sent %d compressed messages", round, n)
		}
	}
}
