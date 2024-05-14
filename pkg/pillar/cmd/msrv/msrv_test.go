// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package msrv_test

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cmd/msrv"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/onsi/gomega"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

func TestRequestPatchEnvelopes(t *testing.T) {
	//	t.Parallel()
	g := gomega.NewGomegaWithT(t)

	logger := logrus.StandardLogger()

	log := base.NewSourceLogObject(logger, "pubsub", 1234)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	appNetworkStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedrouter",
		TopicType:  types.AppNetworkStatus{},
		Persistent: true,
	})
	g.Expect(err).To(gomega.BeNil())
	u, err := uuid.FromString("6ba7b810-9dad-11d1-80b4-000000000000")
	g.Expect(err).To(gomega.BeNil())

	appNetworkStatus.Publish("6ba7b810-9dad-11d1-80b4-000000000001", types.AppNetworkStatus{
		UUIDandVersion: types.UUIDandVersion{
			UUID:    u,
			Version: "1.0",
		},
		AppNetAdapterList: []types.AppNetAdapterStatus{
			{
				AllocatedIPv4Addr: net.ParseIP("192.168.1.1"),
			},
		},
	})

	peInfo, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedagent",
		TopicType:  types.PatchEnvelopeInfoList{},
		Persistent: true,
	})
	g.Expect(err).To(gomega.BeNil())
	peInfo.Publish("global", types.PatchEnvelopeInfoList{
		Envelopes: []types.PatchEnvelopeInfo{
			{
				Name:        "asdf",
				Version:     "asdf",
				AllowedApps: []string{"6ba7b810-9dad-11d1-80b4-000000000000"},
				PatchID:     "6ba7b810-9dad-11d1-80b4-111111111111",
				State:       types.PatchEnvelopeStateActive,
				BinaryBlobs: []types.BinaryBlobCompleted{
					{
						FileName: "abcd",
						FileSha:  "abcd",
						URL:      "a.txt",
					},
				},
			},
		},
	})

	srv := &msrv.Msrv{
		Log:    log,
		PubSub: ps,
		Logger: logger,
	}

	dir, err := ioutil.TempDir("/tmp", "msrv_test")
	g.Expect(err).To(gomega.BeNil())
	defer os.RemoveAll(dir)

	err = srv.Init(dir)
	g.Expect(err).To(gomega.BeNil())

	err = srv.Activate()
	g.Expect(err).To(gomega.BeNil())

	g.Eventually(func() []types.PatchEnvelopeInfo {
		return srv.PatchEnvelopes.Get("6ba7b810-9dad-11d1-80b4-000000000000").Envelopes
	}, 30*time.Second, 10*time.Second).Should(gomega.HaveLen(1))

	handler := srv.MakeMetadataHandler()

	descReq := httptest.NewRequest(http.MethodGet, "/eve/v1/patch/description.json", nil)
	descReq.RemoteAddr = "192.168.1.1:0"
	descResp := httptest.NewRecorder()
	descReqTimes := 42
	for i := 0; i < descReqTimes; i++ {
		handler.ServeHTTP(descResp, descReq)
		g.Expect(descResp.Code).To(gomega.Equal(http.StatusOK))

		defer descResp.Body.Reset()
		var got []msrv.PeInfoToDisplay

		err = json.NewDecoder(descResp.Body).Decode(&got)
		g.Expect(err).To(gomega.BeNil())

		g.Expect(got).To(gomega.BeEquivalentTo(
			[]msrv.PeInfoToDisplay{
				{
					PatchID: "6ba7b810-9dad-11d1-80b4-111111111111",
					Version: "asdf",
					BinaryBlobs: []types.BinaryBlobCompleted{
						{
							FileName:         "abcd",
							FileSha:          "abcd",
							FileMetadata:     "",
							ArtifactMetadata: "",
							URL:              "http://169.254.169.254/eve/v1/patch/download/6ba7b810-9dad-11d1-80b4-111111111111/abcd",
							Size:             0,
						},
					},
				},
			},
		))
	}

	downReq := httptest.NewRequest(http.MethodGet, "/eve/v1/patch/download/6ba7b810-9dad-11d1-80b4-111111111111/abcd", nil)
	downReq.RemoteAddr = "192.168.1.1:0"
	downResp := httptest.NewRecorder()
	downReqTimes := 24
	for i := 0; i < downReqTimes; i++ {
		handler.ServeHTTP(downResp, downReq)
		g.Expect(descResp.Code).To(gomega.Equal(http.StatusOK))
	}

	expected := types.PatchEnvelopeUsage{
		AppUUID:           "6ba7b810-9dad-11d1-80b4-000000000000",
		PatchID:           "6ba7b810-9dad-11d1-80b4-111111111111",
		Version:           "asdf",
		PatchAPICallCount: uint64(descReqTimes),
		DownloadCount:     uint64(downReqTimes),
	}

	srv.PublishPatchEnvelopesUsage()
	subPatchUsage, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "msrv",
		MyAgentName: "test",
		TopicImpl:   types.PatchEnvelopeUsage{},
		Activate:    true,
		Persistent:  true,
	})
	g.Expect(err).To(gomega.BeNil())
	items := subPatchUsage.GetAll()
	item, ok := items["patchEnvelopeUsage:6ba7b810-9dad-11d1-80b4-111111111111-v-asdf-app-6ba7b810-9dad-11d1-80b4-000000000000"]
	g.Expect(ok).To(gomega.BeTrue())
	peUsage, ok := item.(types.PatchEnvelopeUsage)
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(peUsage).To(gomega.BeEquivalentTo(expected))
}

func TestHandleAppInstanceDiscovery(t *testing.T) {
	t.Parallel()
	g := gomega.NewGomegaWithT(t)

	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "pubsub", 1234)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	u, err := uuid.FromString("6ba7b810-9dad-11d1-80b4-000000000000")
	g.Expect(err).ToNot(gomega.HaveOccurred())
	u1, err := uuid.FromString("6ba7b810-9dad-11d1-80b4-000000000001")
	g.Expect(err).ToNot(gomega.HaveOccurred())

	appInstanceStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedmanager",
		TopicType:  types.AppInstanceStatus{},
		Persistent: true,
	})

	a := types.AppInstanceStatus{
		UUIDandVersion: types.UUIDandVersion{
			UUID:    u,
			Version: "1.0",
		},
		AppNetAdapters: []types.AppNetAdapterStatus{
			{
				AllocatedIPv4Addr: net.ParseIP("192.168.1.1"),
				AppNetAdapterConfig: types.AppNetAdapterConfig{
					IfIdx:           2,
					AllowToDiscover: true,
				},
			},
		},
	}
	err = appInstanceStatus.Publish(u.String(), a)
	g.Expect(err).ToNot(gomega.HaveOccurred())
	discoverableNet := types.AppNetAdapterStatus{
		AllocatedIPv4Addr: net.ParseIP("192.168.1.2"),
		VifInfo:           types.VifInfo{VifConfig: types.VifConfig{Vif: "eth0"}},
	}
	a1 := types.AppInstanceStatus{
		UUIDandVersion: types.UUIDandVersion{
			UUID:    u1,
			Version: "1.0",
		},
		AppNetAdapters: []types.AppNetAdapterStatus{discoverableNet},
	}
	err = appInstanceStatus.Publish(u1.String(), a1)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	srv := &msrv.Msrv{
		Log:    log,
		PubSub: ps,
		Logger: logger,
	}

	dir, err := ioutil.TempDir("/tmp", "msrv_test")
	g.Expect(err).ToNot(gomega.HaveOccurred())
	defer os.RemoveAll(dir)

	err = srv.Init(dir)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	err = srv.Activate()
	g.Expect(err).ToNot(gomega.HaveOccurred())

	handler := srv.MakeMetadataHandler()

	descReq := httptest.NewRequest(http.MethodGet, "/eve/v1/discover-network.json", nil)
	descReq.RemoteAddr = "192.168.1.1:0"
	descResp := httptest.NewRecorder()

	handler.ServeHTTP(descResp, descReq)
	g.Expect(descResp.Code).To(gomega.Equal(http.StatusOK))

	defer descResp.Body.Reset()
	var got map[string][]msrv.AppInstDiscovery

	err = json.NewDecoder(descResp.Body).Decode(&got)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	expected := map[string][]msrv.AppInstDiscovery{
		u1.String(): {{
			Port:    discoverableNet.Vif,
			Address: discoverableNet.AllocatedIPv4Addr.String(),
		}},
	}
	g.Expect(got).To(gomega.BeEquivalentTo(expected))
}
