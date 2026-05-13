// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/hex"
	"testing"

	zcert "github.com/lf-edge/eve-api/go/certs"
	"google.golang.org/protobuf/proto"
)

func marshalCerts(t *testing.T, hashes ...[]byte) []byte {
	t.Helper()
	msg := &zcert.ZControllerCert{}
	for _, h := range hashes {
		msg.Certs = append(msg.Certs, &zcert.ZCert{CertHash: h})
	}
	b, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	return b
}

func TestParseKeysFromControllerCerts(t *testing.T) {
	h1 := []byte{0xab, 0xcd}
	h2 := []byte{0xde, 0xad, 0xbe, 0xef}

	t.Run("empty cert set", func(t *testing.T) {
		keys, err := parseKeysFromControllerCerts(marshalCerts(t))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("keys = %v, want empty", keys)
		}
	})

	t.Run("single cert", func(t *testing.T) {
		keys, err := parseKeysFromControllerCerts(marshalCerts(t, h1))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(keys) != 1 || keys[0] != hex.EncodeToString(h1) {
			t.Errorf("keys = %v, want [%s]", keys, hex.EncodeToString(h1))
		}
	})

	t.Run("two certs preserve insertion order", func(t *testing.T) {
		keys, err := parseKeysFromControllerCerts(marshalCerts(t, h1, h2))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{hex.EncodeToString(h1), hex.EncodeToString(h2)}
		if len(keys) != 2 || keys[0] != want[0] || keys[1] != want[1] {
			t.Errorf("keys = %v, want %v", keys, want)
		}
	})

	t.Run("garbage bytes fail unmarshal", func(t *testing.T) {
		_, err := parseKeysFromControllerCerts([]byte("not a protobuf"))
		if err == nil {
			t.Fatal("want error, got nil")
		}
	})
}

func TestCompareControllerCertBytes(t *testing.T) {
	h1 := []byte{0xab, 0xcd}
	h2 := []byte{0xde, 0xad}
	h3 := []byte{0xbe, 0xef}

	tests := []struct {
		name        string
		newBytes    []byte
		prevBytes   []byte
		wantChanged bool
	}{
		{
			name:        "identical bytes",
			newBytes:    marshalCerts(t, h1, h2),
			prevBytes:   marshalCerts(t, h1, h2),
			wantChanged: false,
		},
		{
			name:        "same certs different order",
			newBytes:    marshalCerts(t, h1, h2),
			prevBytes:   marshalCerts(t, h2, h1),
			wantChanged: false,
		},
		{
			name:        "cert added",
			newBytes:    marshalCerts(t, h1, h2, h3),
			prevBytes:   marshalCerts(t, h1, h2),
			wantChanged: true,
		},
		{
			name:        "cert removed",
			newBytes:    marshalCerts(t, h1),
			prevBytes:   marshalCerts(t, h1, h2),
			wantChanged: true,
		},
		{
			name:        "cert swapped",
			newBytes:    marshalCerts(t, h1, h3),
			prevBytes:   marshalCerts(t, h1, h2),
			wantChanged: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := compareControllerCertBytes(tc.newBytes, tc.prevBytes)
			if got != tc.wantChanged {
				t.Errorf("compareControllerCertBytes = %v, want %v", got, tc.wantChanged)
			}
		})
	}
}
