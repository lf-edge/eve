// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package prereqs

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScanForDefaultRoute exercises /proc/net/route parsing for the
// "default route present?" question. The pure scanner is testable
// even though the production reader goes through procNetRoute.
func TestScanForDefaultRoute(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{
			name: "default route present (8 fields, dest+mask zero)",
			in: "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n" +
				"eth0\t00000000\t0102030A\t0003\t0\t0\t0\t00000000\n",
			want: true,
		},
		{
			name: "no default route — only host routes",
			in: "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n" +
				"eth0\t0010A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n",
			want: false,
		},
		{
			name: "fewer than 8 fields per row is skipped",
			in: "Iface\tDestination\n" +
				"eth0\t00000000\n",
			want: false,
		},
		{
			name: "destination zero but mask non-zero is not a default route",
			in: "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n" +
				"eth0\t00000000\t00000000\t0001\t0\t0\t0\t000000FF\n",
			want: false,
		},
		{
			name: "header-only input",
			in:   "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n",
			want: false,
		},
		{
			name: "empty input",
			in:   "",
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scanForDefaultRoute(strings.NewReader(c.in))
			if got != c.want {
				t.Errorf("scanForDefaultRoute = %v, want %v", got, c.want)
			}
		})
	}
}

func TestScanForMountpoint(t *testing.T) {
	mounts := "rootfs / rootfs rw 0 0\n" +
		"/dev/sda1 /var/lib ext4 rw,relatime 0 0\n" +
		"tmpfs /run tmpfs rw 0 0\n"
	cases := []struct {
		mountpoint string
		want       bool
	}{
		{"/", true},
		{"/var/lib", true},
		{"/run", true},
		{"/persist", false},
		{"/var", false}, // substring of /var/lib must not match
	}
	for _, c := range cases {
		t.Run(c.mountpoint, func(t *testing.T) {
			got := scanForMountpoint(strings.NewReader(mounts), c.mountpoint)
			if got != c.want {
				t.Errorf("scanForMountpoint(%q) = %v, want %v",
					c.mountpoint, got, c.want)
			}
		})
	}
}

// TestUUIDRegexp covers the validator that gates waitForValidUUID.
// The shell exposed kube-init to a real bug where /bin/hostname
// returned literal "(none)" or the empty string before onboarding
// completed; the regexp must reject all such transient values.
func TestUUIDRegexp(t *testing.T) {
	good := []string{
		"abcdef01-2345-6789-abcd-ef0123456789",
		"ABCDEF01-2345-6789-ABCD-EF0123456789",
		"00000000-0000-0000-0000-000000000000",
	}
	bad := []string{
		"",
		"(none)",
		"abcdef01-2345-6789-abcd-ef012345678",   // one char short
		"abcdef01-2345-6789-abcd-ef01234567890", // one char long
		"abcdef0g-2345-6789-abcd-ef0123456789",  // 'g' is not hex
		"abcdef01 2345 6789 abcd ef0123456789",  // spaces instead of dashes
		"some.host.name",
	}
	for _, in := range good {
		if !uuidRegexp.MatchString(in) {
			t.Errorf("uuidRegexp rejected valid UUID %q", in)
		}
	}
	for _, in := range bad {
		if uuidRegexp.MatchString(in) {
			t.Errorf("uuidRegexp accepted invalid value %q", in)
		}
	}
}

// TestWitnessZvolReserved pins the three-way answer that decides the
// witness's backing store. A missing device node cannot distinguish
// "never reserved" from "not appeared yet", so the marker decides, and
// an unreadable marker must refuse rather than guess: starting the
// witness on the wrong store discards its etcd identity.
func TestWitnessZvolReserved(t *testing.T) {
	dir := t.TempDir()
	orig := witnessZvolMarker
	t.Cleanup(func() { witnessZvolMarker = orig })

	t.Run("absent marker means vault-backed", func(t *testing.T) {
		witnessZvolMarker = filepath.Join(dir, "absent")
		got, err := witnessZvolReserved()
		if err != nil || got {
			t.Errorf("got (%v, %v), want (false, nil)", got, err)
		}
	})

	t.Run("present marker means zvol", func(t *testing.T) {
		marker := filepath.Join(dir, "reserved")
		if err := os.WriteFile(marker, nil, 0644); err != nil {
			t.Fatalf("write marker: %v", err)
		}
		witnessZvolMarker = marker
		got, err := witnessZvolReserved()
		if err != nil || !got {
			t.Errorf("got (%v, %v), want (true, nil)", got, err)
		}
	})

	t.Run("unreadable marker is an error", func(t *testing.T) {
		notADir := filepath.Join(dir, "file")
		if err := os.WriteFile(notADir, nil, 0644); err != nil {
			t.Fatalf("write: %v", err)
		}
		witnessZvolMarker = filepath.Join(notADir, "marker")
		got, err := witnessZvolReserved()
		if err == nil {
			t.Errorf("got (%v, nil), want an error", got)
		}
	})
}

func TestAddrsContain(t *testing.T) {
	cidr := func(s string) net.Addr {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return &net.IPNet{IP: ip, Mask: n.Mask}
	}
	// What the witness netns actually holds once NIM has plugged the
	// veth: loopback, the cluster address, and a link-local v6.
	addrs := []net.Addr{
		cidr("127.0.0.1/8"),
		cidr("10.244.244.5/24"),
		cidr("fe80::4c0a:b7ff:fe38:d1c3/64"),
	}
	cases := []struct {
		name  string
		addrs []net.Addr
		ip    string
		want  bool
	}{
		{"witness address held", addrs, "10.244.244.5", true},
		{"the seed's address is not ours", addrs, "10.244.244.2", false},
		{"loopback only, no veth yet", addrs[:1], "10.244.244.5", false},
		{"empty netns", nil, "10.244.244.5", false},
		{"unparsable ip", addrs, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := addrsContain(c.addrs, c.ip); got != c.want {
				t.Errorf("addrsContain(_, %q) = %v, want %v", c.ip, got, c.want)
			}
		})
	}
}
