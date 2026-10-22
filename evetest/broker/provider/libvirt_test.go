// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package provider

import "testing"

func TestDomainHasNvram(t *testing.T) {
	cases := []struct {
		name string
		xml  string
		want bool
	}{
		{
			name: "format attribute (real form seen on the broker host)",
			xml:  `<nvram format='raw'>/home/eve-broker/images/eve-x/firmware/OVMF_VARS.fd</nvram>`,
			want: true,
		},
		{
			name: "template attribute",
			xml:  `<nvram template='/usr/share/OVMF/OVMF_VARS.fd'>/path</nvram>`,
			want: true,
		},
		{
			name: "type attribute, self-closing-ish",
			xml:  `<nvram type='file'>`,
			want: true,
		},
		{
			name: "bare tag",
			xml:  `<nvram>/path</nvram>`,
			want: true,
		},
		{
			name: "no nvram element at all",
			xml:  `<domain><os><loader>/usr/share/OVMF/OVMF_CODE.fd</loader></os></domain>`,
			want: false,
		},
		{
			name: "over-broad prefix guard",
			xml:  `<nvramfoo>bar</nvramfoo>`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := domainHasNvram(tc.xml)
			if got != tc.want {
				t.Errorf("domainHasNvram(%q) = %v, want %v", tc.xml, got, tc.want)
			}
		})
	}
}
