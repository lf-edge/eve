// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dockerfilefrom

import (
	"reflect"
	"strings"
	"testing"
)

func TestScanFromSet(t *testing.T) {
	cases := []struct {
		name       string
		dockerfile string
		fromSet    []string
	}{
		{
			name:       "plain FROM",
			dockerfile: "FROM alpine:3.20\n",
			fromSet:    []string{"alpine:3.20"},
		},
		{
			name: "ARG default expansion",
			dockerfile: "ARG ALPINE_VERSION=3.20\n" +
				"FROM lfedge/eve-alpine:${ALPINE_VERSION}-base\n",
			fromSet: []string{"lfedge/eve-alpine:3.20-base"},
		},
		{
			name: "dollar form not expanded",
			dockerfile: "ARG TAG=1.0\n" +
				"FROM node:$TAG\n",
			fromSet: []string{"node:$TAG"},
		},
		{
			name: "platform flag skipped",
			dockerfile: "ARG GO_VERSION=1.22\n" +
				"FROM --platform=${BUILDPLATFORM} golang:${GO_VERSION}-alpine AS base\n",
			fromSet: []string{"golang:1.22-alpine"},
		},
		{
			name: "scratch and digest",
			dockerfile: "FROM scratch AS out\n" +
				"FROM alpine@sha256:abc123\n",
			fromSet: []string{"scratch", "alpine@sha256:abc123"},
		},
		{
			name: "continuation across lines",
			dockerfile: "FROM \\\n" +
				"    alpine:3.20\n",
			fromSet: []string{"alpine:3.20"},
		},
		{
			name: "comments and blanks ignored",
			dockerfile: "# comment\n\n" +
				"FROM busybox\n" +
				"# trailing comment\n",
			fromSet: []string{"busybox"},
		},
		{
			name: "valueless ARG leaves undefined reference",
			dockerfile: "ARG EVE_KERNEL\n" +
				"FROM ${EVE_KERNEL} AS kernel\n",
			fromSet: []string{""},
		},
		{
			name: "stage-level ARG not expanded",
			dockerfile: "FROM alpine:3.20\n" +
				"ARG LATER=x\n" +
				"FROM ghcr.io/o:${LATER}\n",
			fromSet: []string{"alpine:3.20", "ghcr.io/o:${LATER}"},
		},
		{
			name: "comment inside continuation skipped",
			dockerfile: "FROM \\\n" +
				"# swallow\n" +
				"    alpine:3.20\n",
			fromSet: []string{"alpine:3.20"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Scan(strings.NewReader(tc.dockerfile))
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if !reflect.DeepEqual(res.FromSet, tc.fromSet) {
				t.Fatalf("FromSet = %q, want %q", res.FromSet, tc.fromSet)
			}
		})
	}
}

func TestScanArgs(t *testing.T) {
	dockerfile := "ARG BUILD_PKGS=\"git gcc \\\n    linux-headers\"\n" +
		"ARG V=one\n" +
		"ARG V\n" +
		"ARG UNDEF\n" +
		"FROM lfedge/eve-builder:${BUILD_PKGS}-x\n" +
		"ARG AFTER=y\n"
	res, err := Scan(strings.NewReader(dockerfile))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	wantArgs := map[string]string{
		// continuation indentation is preserved, quotes included
		"BUILD_PKGS": "\"git gcc     linux-headers\"",
		// valued redeclaration later in the file replaces the default
		"V":     "one",
		"UNDEF": "",
	}
	if !reflect.DeepEqual(res.Args, wantArgs) {
		t.Fatalf("Args = %q, want %q", res.Args, wantArgs)
	}
	if got, want := res.FromSet, []string{"lfedge/eve-builder:\"git gcc     linux-headers\"-x"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("FromSet = %q, want %q", got, want)
	}
}

func TestScanValuelessRedeclarationKeepsDefault(t *testing.T) {
	// A valueless redeclaration must not clobber an earlier default
	// (buildkit setArgs semantics).
	dockerfile := "ARG TAG=one\n" +
		"ARG TAG\n" +
		"FROM image:${TAG}\n"
	res, err := Scan(strings.NewReader(dockerfile))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Args["TAG"] != "one" {
		t.Fatalf("Args[TAG] = %q, want \"one\"", res.Args["TAG"])
	}
	if got, want := res.FromSet, []string{"image:one"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("FromSet = %q, want %q", got, want)
	}
}

func TestScanEscapeDirective(t *testing.T) {
	dockerfile := "# escape=`\n" +
		"FROM `\n" +
		"    alpine:3.20\n"
	res, err := Scan(strings.NewReader(dockerfile))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got, want := res.FromSet, []string{"alpine:3.20"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("FromSet = %q, want %q", got, want)
	}
}

func TestScanEmpty(t *testing.T) {
	for _, in := range []string{"", "\n", "# only a comment\n"} {
		res, err := Scan(strings.NewReader(in))
		if err != nil {
			t.Fatalf("Scan(%q): %v", in, err)
		}
		if len(res.FromSet) != 0 {
			t.Fatalf("Scan(%q) FromSet = %q, want none", in, res.FromSet)
		}
	}
}

func TestExpand(t *testing.T) {
	lookup := func(name string) (string, bool) {
		switch name {
		case "TARGETARCH":
			return "amd64", true
		case "GO_VERSION":
			return "1.22", true
		}
		return "", false
	}
	cases := []struct {
		name string
		word string
		want string
	}{
		{"no refs", "alpine:3.20", "alpine:3.20"},
		{"braced ref", "golang:${GO_VERSION}-alpine", "golang:1.22-alpine"},
		{"bare ref", "lfedge/eve-xen-tools:$XENTOOLS", "lfedge/eve-xen-tools:"},
		{"bare ref in middle", "target-$TARGETARCH", "target-amd64"},
		{"bare ref with trailing", "node:$TARGETARCH:latest", "node:amd64:latest"},
		{"undefined braced", "image:${NOPE}", "image:"},
		{"undefined bare", "$NOPE", ""},
		{"double dollar", "$$VAR", "$"},
		{"escaped dollar", `\$VAR`, "$VAR"},
		{"escaped brace", `\${VAR}`, "${VAR}"},
		{"mixed", "a$1b${TARGETARCH}c$NOPE d", "aamd64c d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Expand(tc.word, lookup); got != tc.want {
				t.Fatalf("Expand(%q) = %q, want %q", tc.word, got, tc.want)
			}
		})
	}
}
