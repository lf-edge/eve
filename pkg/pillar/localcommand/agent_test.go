// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package localcommand

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/lf-edge/eve-api/go/profile"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

func newTestAgent(t *testing.T) *LocalCmdAgent {
	t.Helper()
	lc := &LocalCmdAgent{
		ConstructorArgs: ConstructorArgs{
			Log: base.NewSourceLogObject(logrus.New(), t.Name(), 0),
		},
		globalConfig: types.DefaultConfigItemValueMap(),
	}
	for _, ticker := range []**taskTicker{
		&lc.profileTicker, &lc.radioTicker, &lc.appInfoTicker,
		&lc.devInfoTicker, &lc.networkTicker, &lc.appBootInfoTicker,
	} {
		*ticker = newTaskTicker(time.Hour)
		t.Cleanup((*ticker).tickerHandle.StopTicker)
	}
	lc.initializeSigHandler()
	return lc
}

func TestUpdateLpsConfigRequiresToken(t *testing.T) {
	lc := newTestAgent(t)
	const address = "192.0.2.1:8888"
	for _, step := range []struct {
		name    string
		token   string
		enabled bool
	}{
		{"missing token", "", false},
		{"provision token", "secret", true},
		{"clear token", "", false},
		{"restore token", "replacement", true},
	} {
		t.Run(step.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			lc.sigHandlerCancel = cancel
			if lc.lpsURL != nil {
				lc.lpsAddresses.addrsByIface = map[string][]lpsAddress{
					"test": {{destURL: lc.lpsURL}},
				}
			}
			if err := lc.UpdateLpsConfig("global", address, step.token); err != nil {
				t.Fatal(err)
			}
			if got := lc.lpsURL != nil; got != step.enabled {
				t.Fatalf("LPS enabled = %v, want %v", got, step.enabled)
			}
			if step.enabled {
				if lc.lpsConfig.LpsAddress != address {
					t.Fatalf("LPS address = %q", lc.lpsConfig.LpsAddress)
				}
			} else {
				if !lc.lpsAddresses.empty() {
					t.Fatal("disabled LPS retained discovered addresses")
				}
				// No client is configured: return before making a request.
				if config, _ := lc.getLocalProfileConfig(); config != nil {
					t.Fatal("disabled LPS returned a profile")
				}
				if cmd, _ := lc.postDevInfo(); cmd != nil {
					t.Fatal("disabled LPS returned a device command")
				}
			}
			if step.name == "clear token" && ctx.Err() == nil {
				t.Fatal("clearing the token did not cancel the signal stream")
			}
			if lc.currentProfile != "global" {
				t.Fatalf("active profile = %q, want global", lc.currentProfile)
			}
		})
	}
}

func TestRejectUnauthenticatedNetworkConfig(t *testing.T) {
	for _, tc := range []struct {
		name, configured, received string
	}{
		{"both empty", "", ""},
		{"unconfigured token", "", "attacker"},
		{"missing response token", "secret", ""},
		{"incorrect response token", "secret", "attacker"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lc := newTestAgent(t)
			lc.lpsConfig.LpsToken = tc.configured
			if err := lc.applyLocalNetworkConfig(&profile.LocalNetworkConfig{
				ServerToken: tc.received,
			}, time.Now()); err == nil {
				t.Fatal("accepted an unauthenticated network configuration")
			}
		})
	}
}

func TestLocalProfileResponseAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name, configured, received string
		accepted                   bool
	}{
		{"both empty", "", "", false},
		{"unconfigured token", "", "attacker", false},
		{"missing response token", "secret", "", false},
		{"incorrect response token", "secret", "attacker", false},
		{"matching token", "secret", "secret", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := proto.Marshal(&profile.LocalProfile{
				ServerToken: tc.received, LocalProfile: "local",
			})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != profileURLPath {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", controllerconn.ContentTypeProto)
				_, _ = w.Write(payload)
			}))
			defer server.Close()
			lc := newTestAgent(t)
			lc.lpsConfig.LpsToken = tc.configured
			lc.lpsURL, err = url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			lc.lpsAddresses.addrsByIface = map[string][]lpsAddress{
				"lo": {{destURL: lc.lpsURL}},
			}
			lc.CtrlClient = controllerconn.NewClient(lc.Log, controllerconn.ClientOptions{
				NetworkSendTimeout: time.Second * 5,
			})
			if lc.tc.startTask() {
				t.Fatal("task unexpectedly paused")
			}
			defer lc.tc.endTask()
			received, discarded := lc.getLocalProfileConfig()
			if discarded {
				t.Fatal("response unexpectedly discarded")
			}
			if got := received != nil; got != tc.accepted {
				t.Fatalf("response accepted = %v, want %v", got, tc.accepted)
			}
		})
	}
}
