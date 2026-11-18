// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package localcommand

import (
	"testing"

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
			lc := &LocalCmdAgent{}
			saved, err := lc.parseLocalProfile(data)
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
