// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package msrv_test

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
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

func TestPostKubeconfig(t *testing.T) {
	t.Parallel()
	g := gomega.NewGomegaWithT(t)

	logger := logrus.StandardLogger()

	log := base.NewSourceLogObject(logger, "pubsub", 1234)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	appNetworkStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedrouter",
		TopicType:  types.AppNetworkStatus{},
		Persistent: true,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())
	u, err := uuid.FromString("6ba7b810-9dad-11d1-80b4-000000000000")
	g.Expect(err).ToNot(gomega.HaveOccurred())
	err = appNetworkStatus.Publish("6ba7b810-9dad-11d1-80b4-000000000001", types.AppNetworkStatus{
		UUIDandVersion: types.UUIDandVersion{
			UUID:    u,
			Version: "1.0",
		},
		AppNetAdapterList: []types.AppNetAdapterStatus{
			{
				AssignedAddresses: types.AssignedAddrs{
					IPv4Addrs: []types.AssignedAddr{
						{
							Address: net.ParseIP("192.168.1.1"),
						},
					},
					IPv6Addrs: nil,
				},
			},
		},
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	devNetStatusPub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "nim",
		TopicType:  types.DeviceNetworkStatus{},
		Persistent: true,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())
	devNetStat := types.DeviceNetworkStatus{
		Ports: []types.NetworkPortStatus{
			{
				IfName: "eth0",
				AddrInfoList: []types.AddrInfo{
					{
						Addr: net.ParseIP("192.168.1.1"),
					},
				},
			},
		},
	}
	err = devNetStatusPub.Publish("6ba7b810-9dad-11d1-80b4-000000000002", devNetStat)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	netInstance, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedrouter",
		TopicType:  types.NetworkInstanceStatus{},
		Persistent: true,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())
	niStatus := types.NetworkInstanceStatus{
		NetworkInstanceInfo: types.NetworkInstanceInfo{
			IPAssignments: map[string]types.AssignedAddrs{"k": {
				IPv4Addrs: []types.AssignedAddr{
					{
						Address: net.ParseIP("192.168.1.1"),
					},
				},
			}},
		},
	}
	err = netInstance.Publish("6ba7b810-9dad-11d1-80b4-000000000003", niStatus)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	srv := &msrv.Msrv{
		Log:    log,
		PubSub: ps,
		Logger: logger,
	}

	dir, err := os.MkdirTemp("/tmp", "msrv_test")
	g.Expect(err).ToNot(gomega.HaveOccurred())
	defer os.RemoveAll(dir)

	err = srv.Init(dir, true)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	err = srv.Activate()
	g.Expect(err).ToNot(gomega.HaveOccurred())

	handler := srv.MakeMetadataHandler()

	var jsonStr = []byte(`{"hello":"world"}`)
	descReq := httptest.NewRequest(http.MethodPost, "/eve/v1/kubeconfig", bytes.NewBuffer(jsonStr))
	descReq.Header.Set("Content-Type", "application/json")
	descReq.RemoteAddr = "192.168.1.1:0"
	descResp := httptest.NewRecorder()

	handler.ServeHTTP(descResp, descReq)
	g.Expect(descResp.Code).To(gomega.Equal(http.StatusOK))

	subPatchUsage, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "msrv",
		MyAgentName: "test",
		TopicImpl:   types.AppInstMetaData{},
		Activate:    true,
		Persistent:  true,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	items := subPatchUsage.GetAll()
	expected := types.AppInstMetaData{
		AppInstUUID: u,
		Data:        jsonStr,
		Type:        types.AppInstMetaDataTypeKubeConfig,
	}

	g.Expect(items[expected.Key()]).To(gomega.BeEquivalentTo(expected))
}

func TestRequestPatchEnvelopes(t *testing.T) {
	t.Parallel()
	g := gomega.NewGomegaWithT(t)

	logger := logrus.StandardLogger()

	log := base.NewSourceLogObject(logger, "pubsub", 1234)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	appNetworkStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedrouter",
		TopicType:  types.AppNetworkStatus{},
		Persistent: true,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())
	u, err := uuid.FromString("6ba7b810-9dad-11d1-80b4-000000000000")
	g.Expect(err).ToNot(gomega.HaveOccurred())

	err = appNetworkStatus.Publish("6ba7b810-9dad-11d1-80b4-000000000001", types.AppNetworkStatus{
		UUIDandVersion: types.UUIDandVersion{
			UUID:    u,
			Version: "1.0",
		},
		AppNetAdapterList: []types.AppNetAdapterStatus{
			{
				AssignedAddresses: types.AssignedAddrs{
					IPv4Addrs: []types.AssignedAddr{
						{
							Address: net.ParseIP("192.168.1.1"),
						},
					},
					IPv6Addrs: nil,
				},
			},
		},
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	peInfo, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedagent",
		TopicType:  types.PatchEnvelopeInfoList{},
		Persistent: true,
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())
	err = peInfo.Publish("global", types.PatchEnvelopeInfoList{
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
				CipherBlobs: []types.BinaryCipherBlob{
					{
						EncType: types.BlobEncrytedTypeInline,
						Inline: &types.BinaryBlobCompleted{
							FileName: "abcd2",
							FileSha:  "abcd2",
							URL:      "a2.txt",
						},
					},
					{
						EncType: types.BlobEncrytedTypeVolume,
						Volume: &types.BinaryBlobVolumeRef{
							FileName:         "abcd3a",
							ImageName:        "abcd3b",
							FileMetadata:     "abcd3c",
							ArtifactMetadata: "abcd3d",
							ImageID:          "abcd3e",
						},
					},
				},
			},
		},
	})
	g.Expect(err).ToNot(gomega.HaveOccurred())

	srv := &msrv.Msrv{
		Log:    log,
		PubSub: ps,
		Logger: logger,
	}

	dir, err := os.MkdirTemp("/tmp", "msrv_test")
	g.Expect(err).ToNot(gomega.HaveOccurred())
	defer os.RemoveAll(dir)

	err = srv.Init(dir, true)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	err = srv.Activate()
	g.Expect(err).ToNot(gomega.HaveOccurred())

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
		g.Expect(err).ToNot(gomega.HaveOccurred())

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
						{
							FileName:         "abcd2",
							FileSha:          "abcd2",
							FileMetadata:     "",
							ArtifactMetadata: "",
							URL:              "http://169.254.169.254/eve/v1/patch/download/6ba7b810-9dad-11d1-80b4-111111111111/abcd2",
							Size:             0,
						},
					},
					VolumeRefs: []types.BinaryBlobVolumeRef{
						{
							FileName:         "abcd3a",
							ImageName:        "abcd3b",
							FileMetadata:     "abcd3c",
							ArtifactMetadata: "abcd3d",
							ImageID:          "abcd3e",
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
	g.Expect(err).ToNot(gomega.HaveOccurred())
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
	u2, err := uuid.FromString("6ba7b810-9dad-11d1-80b4-000000000002")
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
				AssignedAddresses: types.AssignedAddrs{
					IPv4Addrs: []types.AssignedAddr{
						{
							Address: net.ParseIP("192.168.1.1"),
						},
					},
					IPv6Addrs: nil,
				},
				AppNetAdapterConfig: types.AppNetAdapterConfig{
					IfIdx:           2,
					AllowToDiscover: true,
				},
			},
		},
	}
	err = appInstanceStatus.Publish(u.String(), a)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	// AppInstance which is not allowed to discover
	b := types.AppInstanceStatus{
		UUIDandVersion: types.UUIDandVersion{
			UUID:    u2,
			Version: "1.0",
		},
		AppNetAdapters: []types.AppNetAdapterStatus{
			{
				AssignedAddresses: types.AssignedAddrs{
					IPv4Addrs: []types.AssignedAddr{
						{
							Address: net.ParseIP("192.168.1.3"),
						},
					},
					IPv6Addrs: nil,
				},
				AppNetAdapterConfig: types.AppNetAdapterConfig{
					IfIdx:           2,
					AllowToDiscover: false,
				},
			},
		},
	}
	err = appInstanceStatus.Publish(u2.String(), b)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	discoverableNet := types.AppNetAdapterStatus{
		AssignedAddresses: types.AssignedAddrs{
			IPv4Addrs: []types.AssignedAddr{
				{
					Address: net.ParseIP("192.168.1.2"),
				},
			},
			IPv6Addrs: nil,
		},
		VifInfo: types.VifInfo{VifConfig: types.VifConfig{Vif: "eth0"}},
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

	dir, err := os.MkdirTemp("/tmp", "msrv_test")
	g.Expect(err).ToNot(gomega.HaveOccurred())
	defer os.RemoveAll(dir)

	err = srv.Init(dir, true)
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
			Address: discoverableNet.AssignedAddresses.IPv4Addrs[0].Address.String(),
		}},

		u2.String(): {{
			Port:    "",
			Address: b.AppNetAdapters[0].AssignedAddresses.IPv4Addrs[0].Address.String(),
		}},
	}
	g.Expect(got).To(gomega.BeEquivalentTo(expected))

	descReq = httptest.NewRequest(http.MethodGet, "/eve/v1/discover-network.json", nil)
	descReq.RemoteAddr = "192.168.1.3:0"
	descResp = httptest.NewRecorder()
	handler.ServeHTTP(descResp, descReq)
	g.Expect(descResp.Code).To(gomega.Equal(http.StatusForbidden))
}

func TestReverseProxy(t *testing.T) {
	t.Parallel()
	g := gomega.NewGomegaWithT(t)

	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "pubsub", 1234)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	srv := &msrv.Msrv{
		Log:    log,
		PubSub: ps,
		Logger: logger,
	}

	dir, err := os.MkdirTemp("/tmp", "msrv_test")
	g.Expect(err).ToNot(gomega.HaveOccurred())
	defer os.RemoveAll(dir)

	err = srv.Init(dir, true)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	err = srv.Activate()
	g.Expect(err).ToNot(gomega.HaveOccurred())

	handler := srv.MakeMetadataHandler()

	var count int32
	backend := &http.Server{
		Addr: "localhost:9100",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&count, 1)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("proxied response"))
		}),
	}

	ln, err := net.Listen("tcp", "localhost:9100")
	g.Expect(err).ToNot(gomega.HaveOccurred())

	go func() {
		_ = backend.Serve(ln)
	}()
	defer func() {
		_ = backend.Close()
	}()

	makeReq := func(ip string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = ip + ":12345"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	ip1 := "10.0.0.1"
	ip2 := "10.0.0.2"

	// 1st request from each IP should succeed
	rr := makeReq(ip1)
	g.Expect(rr.Code).To(gomega.Equal(http.StatusOK))
	// Burst of requests, which should be rate limited
	for range 10 {
		_ = makeReq(ip1)
	}
	// request after burst should fail
	rr = makeReq(ip1)
	g.Expect(rr.Code).To(gomega.Equal(http.StatusTooManyRequests))

	rr = makeReq(ip2)
	g.Expect(rr.Code).To(gomega.Equal(http.StatusOK))

}
