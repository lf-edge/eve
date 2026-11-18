// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/sirupsen/logrus"
	"testing"
	"time"

	"github.com/lf-edge/eve-api/go/profile"
	"google.golang.org/protobuf/proto"
)

func TestSavedLocalProfileRequiresToken(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"legacy empty token", ""},
		{"authenticated profile", "secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := proto.Marshal(&profile.LocalProfile{
				LocalProfile: "local",
				ServerToken:  tc.token,
			})
			if err != nil {
				t.Fatal(err)
			}
			// Saved profiles are decoded before the controller supplies LPS config.
			saved, err := parseLocalProfile(data)
			if tc.token == "" {
				if err == nil || saved != nil {
					t.Fatal("accepted a saved profile with an empty token")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if saved.GetLocalProfile() != "local" || saved.GetServerToken() != tc.token {
				t.Fatalf("unexpected saved profile: %v", saved)
			}
		})
	}
}

func TestLocalProfileConfigRequiresToken(t *testing.T) {
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, "zedagent", 1234)
	ctx := &getconfigContext{}
	ctx.sideController.localAppInfoPOSTTicker = flextimer.NewRangeTicker(time.Hour, 2*time.Hour)
	ctx.sideController.localDevInfoPOSTTicker = flextimer.NewRangeTicker(time.Hour, 2*time.Hour)
	ctx.sideController.localAppBootInfoPOSTTicker = flextimer.NewRangeTicker(time.Hour, 2*time.Hour)
	defer ctx.sideController.localAppInfoPOSTTicker.StopTicker()
	defer ctx.sideController.localDevInfoPOSTTicker.StopTicker()
	defer ctx.sideController.localAppBootInfoPOSTTicker.StopTicker()
	for _, token := range []string{"", "secret", "", "restored"} {
		config := &zconfig.EdgeDevConfig{LocalProfileServer: "192.0.2.1:8888", ProfileServerToken: token}
		parseProfile(ctx, config)
		wantServer := config.LocalProfileServer
		if token == "" {
			wantServer = ""
		}
		if ctx.sideController.localProfileServer != wantServer || ctx.sideController.profileServerToken != token {
			t.Fatalf("token %q: server=%q token=%q", token, ctx.sideController.localProfileServer, ctx.sideController.profileServerToken)
		}
		if config.LocalProfileServer != "192.0.2.1:8888" {
			t.Fatal("modified controller configuration")
		}
	}
}
