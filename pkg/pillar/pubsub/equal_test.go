// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type bytesItem struct {
	Name  string
	Data  []byte
	Certs [][]byte
}

// TestEqualOptsSameResult checks that equalOpts does not change what
// cmp.Equal finds equal.
func TestEqualOptsSameResult(t *testing.T) {
	items := []bytesItem{
		{Name: "a"},
		{Name: "a", Data: []byte{}},
		{Name: "a", Data: []byte("x")},
		{Name: "a", Data: []byte("y")},
		{Name: "a", Data: []byte("xy")},
		{Name: "a", Certs: [][]byte{nil}},
		{Name: "a", Certs: [][]byte{{}}},
		{Name: "a", Certs: [][]byte{[]byte("c1"), []byte("c2")}},
		{Name: "a", Certs: [][]byte{[]byte("c2"), []byte("c1")}},
		{Name: "b", Data: []byte("x")},
	}
	for i, a := range items {
		for j, b := range items {
			want := cmp.Equal(a, b)
			if got := cmp.Equal(a, b, equalOpts); got != want {
				t.Errorf("items %d and %d: equal %v with equalOpts, %v without", i, j, got, want)
			}
		}
	}
}

// TestEqualOptsFast checks that byte slices which differ everywhere are
// compared in time: without equalOpts, cmp.Equal is quadratic in their
// length.
func TestEqualOptsFast(t *testing.T) {
	a := bytesItem{Data: bytes.Repeat([]byte("ab"), 512<<10)}
	b := bytesItem{Data: bytes.Repeat([]byte("ba"), 512<<10)}
	start := time.Now()
	if cmp.Equal(a, b, equalOpts) {
		t.Fatal("different byte slices compared equal")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("comparing 1MB byte slices took %v", d)
	}
}
