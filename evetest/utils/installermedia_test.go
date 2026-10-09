// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"testing"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

// TestInstallerMediaCapability pins the one table both sides of the capability
// gate read: every real medium has its own capability, and "no medium" (a live
// image) has none.
func TestInstallerMediaCapability(t *testing.T) {
	cases := []struct {
		media  api.InstallerMedia
		want   api.Capability
		wantOK bool
	}{
		{api.InstallerMedia_INSTALLER_MEDIA_RAW, api.Capability_CAPABILITY_LOCAL_INSTALLER_RAW, true},
		{api.InstallerMedia_INSTALLER_MEDIA_ISO, api.Capability_CAPABILITY_LOCAL_INSTALLER_ISO, true},
		{api.InstallerMedia_INSTALLER_MEDIA_NET, api.Capability_CAPABILITY_LOCAL_INSTALLER_NET, true},
		{api.InstallerMedia_INSTALLER_MEDIA_UNSPECIFIED, api.Capability_CAPABILITY_UNSPECIFIED, false},
		{api.InstallerMedia(42), api.Capability_CAPABILITY_UNSPECIFIED, false},
	}
	for _, c := range cases {
		t.Run(c.media.String(), func(t *testing.T) {
			got, ok := InstallerMediaCapability(c.media)
			if got != c.want || ok != c.wantOK {
				t.Errorf("InstallerMediaCapability(%v) = (%v, %v), want (%v, %v)",
					c.media, got, ok, c.want, c.wantOK)
			}
		})
	}
}

func TestInstallerMediaName(t *testing.T) {
	for media, want := range map[api.InstallerMedia]string{
		api.InstallerMedia_INSTALLER_MEDIA_RAW: "raw",
		api.InstallerMedia_INSTALLER_MEDIA_ISO: "ISO",
		api.InstallerMedia_INSTALLER_MEDIA_NET: "NET",
	} {
		if got := InstallerMediaName(media); got != want {
			t.Errorf("InstallerMediaName(%v) = %q, want %q", media, got, want)
		}
	}
}
