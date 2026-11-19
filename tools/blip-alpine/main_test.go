// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openshift/imagebuilder"
)

const (
	alpine = "lfedge/eve-alpine"
	oldTag = "61283a3a978a7cdc9073a1ba678717fc3ea1fe97"
	newTag = "0123456789abcdef0123456789abcdef01234567"
)

// tags spells out the OLD and NEW that the Dockerfiles of the tests use
// in place of the two hashes.
func tags(dockerfile string) string {
	return strings.NewReplacer("OLD", oldTag, "NEW", newTag).Replace(dockerfile)
}

func TestRetag(t *testing.T) {
	cases := []struct {
		name string
		// lfedge/eve-alpine and NEW unless set
		image, tag string
		in, want   string
	}{
		{
			name: "FROM with a flag and a stage name",
			in: `FROM --platform=$BUILDPLATFORM lfedge/eve-alpine:OLD AS build
RUN true
`,
			want: `FROM --platform=$BUILDPLATFORM lfedge/eve-alpine:NEW AS build
RUN true
`,
		},
		{
			name: "ARG default that several stages are built from",
			in: `ARG EVE_ALPINE_IMAGE=lfedge/eve-alpine:OLD

FROM ${EVE_ALPINE_IMAGE} AS native
FROM --platform=${BUILDPLATFORM} ${EVE_ALPINE_IMAGE} AS cross
`,
			want: `ARG EVE_ALPINE_IMAGE=lfedge/eve-alpine:NEW

FROM ${EVE_ALPINE_IMAGE} AS native
FROM --platform=${BUILDPLATFORM} ${EVE_ALPINE_IMAGE} AS cross
`,
		},
		{
			name: "comments, blank lines, spacing and continuation lines stay",
			in: `# Copyright (c) 2026 Zededa, Inc.

ARG PKGS="git gcc \
          make"

FROM lfedge/eve-alpine:OLD  AS build
# copy the files
RUN while read -r x; do \
        # comment inside the command
        cp "$x" /out; \
    done < /list
`,
			want: `# Copyright (c) 2026 Zededa, Inc.

ARG PKGS="git gcc \
          make"

FROM lfedge/eve-alpine:NEW  AS build
# copy the files
RUN while read -r x; do \
        # comment inside the command
        cp "$x" /out; \
    done < /list
`,
		},
		{
			name: "the tag outside an image reference is left alone",
			in: `# built from lfedge/eve-alpine:OLD
FROM lfedge/eve-alpine:OLD
ENV REVISION=OLD
RUN echo lfedge/eve-alpine:OLD
`,
			want: `# built from lfedge/eve-alpine:OLD
FROM lfedge/eve-alpine:NEW
ENV REVISION=OLD
RUN echo lfedge/eve-alpine:OLD
`,
		},
		{
			name: "another image with the same tag is left alone",
			in: `FROM lfedge/eve-alpine:OLD AS alpine
FROM lfedge/eve-alpine-base:OLD AS base
`,
			want: `FROM lfedge/eve-alpine:NEW AS alpine
FROM lfedge/eve-alpine-base:OLD AS base
`,
		},
		{
			name: "tag in an ARG of its own",
			in: `ARG ALPINE_TAG=OLD
FROM lfedge/eve-alpine:${ALPINE_TAG}
`,
			want: `ARG ALPINE_TAG=NEW
FROM lfedge/eve-alpine:${ALPINE_TAG}
`,
		},
		{
			name: "quoted ARG default",
			in: `ARG EVE_ALPINE_IMAGE="lfedge/eve-alpine:OLD"
FROM ${EVE_ALPINE_IMAGE}
`,
			want: `ARG EVE_ALPINE_IMAGE="lfedge/eve-alpine:NEW"
FROM ${EVE_ALPINE_IMAGE}
`,
		},
		{
			name: "COPY --from and RUN --mount",
			in: `FROM scratch
COPY --from=lfedge/eve-alpine:OLD /bin/busybox /bin/
RUN --mount=type=bind,from=lfedge/eve-alpine:OLD,target=/mnt true
`,
			want: `FROM scratch
COPY --from=lfedge/eve-alpine:NEW /bin/busybox /bin/
RUN --mount=type=bind,from=lfedge/eve-alpine:NEW,target=/mnt true
`,
		},
		{
			name: "reference on a continuation line",
			in: `FROM \
    lfedge/eve-alpine:OLD \
    AS build
`,
			want: `FROM \
    lfedge/eve-alpine:NEW \
    AS build
`,
		},
		{
			name: "CRLF line endings and no newline at the end",
			in:   "FROM lfedge/eve-alpine:OLD AS build\r\nRUN true",
			want: "FROM lfedge/eve-alpine:NEW AS build\r\nRUN true",
		},
		{
			name: "placeholders of a Dockerfile.in",
			in: `FROM lfedge/eve-alpine:OLD AS tools
# hadolint ignore=DL3006
FROM MKISO_TAG as iso
COPY --from=iso / /
`,
			want: `FROM lfedge/eve-alpine:NEW AS tools
# hadolint ignore=DL3006
FROM MKISO_TAG as iso
COPY --from=iso / /
`,
		},
		{
			name:  "every tag that the image has",
			image: "alpine",
			tag:   "3.22",
			in: `FROM alpine:3.20 AS a
FROM alpine:3.21 AS b
FROM alpine:3.22 AS c
`,
			want: `FROM alpine:3.22 AS a
FROM alpine:3.22 AS b
FROM alpine:3.22 AS c
`,
		},
		{
			name:  "tag that occurs in the name of the image and elsewhere",
			image: "registry1/app",
			tag:   "2",
			in: `FROM registry1/app:1 AS a1
COPY --from=registry1/app:1 /x1 /y1
`,
			want: `FROM registry1/app:2 AS a1
COPY --from=registry1/app:2 /x1 /y1
`,
		},
		{
			name: "image that has the tag already",
			in: `FROM lfedge/eve-alpine:NEW AS build
`,
			want: `FROM lfedge/eve-alpine:NEW AS build
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			image, tag := alpine, newTag
			if tc.image != "" {
				image, tag = tc.image, tc.tag
			}
			got, err := retag([]byte(tags(tc.in)), image, tag)
			if err != nil {
				t.Fatalf("retag: %v", err)
			}
			if string(got) != tags(tc.want) {
				t.Fatalf("got:\n%s\nwant:\n%s", got, tags(tc.want))
			}
		})
	}
}

func TestRetagRefuses(t *testing.T) {
	cases := []struct {
		name, in string
	}{
		{
			name: "no reference to the image",
			in:   "FROM lfedge/eve-alpine-base:OLD\n",
		},
		{
			name: "image only in a comment and a command",
			in: `# lfedge/eve-alpine:OLD
FROM scratch
RUN echo lfedge/eve-alpine:OLD
`,
		},
		{
			name: "reference without a tag",
			in:   "FROM lfedge/eve-alpine AS build\n",
		},
		{
			name: "ARG that tags another image as well",
			in: `ARG TAG=OLD
FROM lfedge/eve-alpine:${TAG} AS alpine
FROM lfedge/eve-alpine-base:${TAG} AS base
`,
		},
		{
			name: "tag that the Dockerfile does not spell out",
			in:   "FROM lfedge/eve-alpine:${TARGETARCH}\n",
		},
		{
			name: "tag from an ARG without a default",
			in: `ARG TAG
FROM lfedge/eve-alpine:${TAG}
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := retag([]byte(tags(tc.in)), alpine, newTag)
			if err == nil {
				t.Fatalf("retag gave no error, but:\n%s", got)
			}
		})
	}
}

func TestUnparse(t *testing.T) {
	t.Run("unchanged tree gives the text back", func(t *testing.T) {
		src := "# syntax=docker/dockerfile:1\n\nFROM alpine:3.20  AS a\n# why\nRUN a && \\\n    # how\n    b\n\n"
		root, err := imagebuilder.ParseDockerfile(strings.NewReader(src))
		if err != nil {
			t.Fatal(err)
		}
		got, err := unparse([]byte(src), root)
		if err != nil {
			t.Fatalf("unparse: %v", err)
		}
		if string(got) != src {
			t.Fatalf("got:\n%q\nwant:\n%q", got, src)
		}
	})

	t.Run("changed word and flag are written where they belong", func(t *testing.T) {
		// "a" occurs in FROM, alpine and AS before it is the stage name
		src := "FROM alpine AS a\nCOPY --from=a /x /y\n"
		root, err := imagebuilder.ParseDockerfile(strings.NewReader(src))
		if err != nil {
			t.Fatal(err)
		}
		fromNode, copyNode := root.Children[0], root.Children[1]
		fromNode.Next.Next.Next.Value = "base"
		copyNode.Flags[0] = "--from=base"
		got, err := unparse([]byte(src), root)
		if err != nil {
			t.Fatalf("unparse: %v", err)
		}
		if want := "FROM alpine AS base\nCOPY --from=base /x /y\n"; string(got) != want {
			t.Fatalf("got:\n%s\nwant:\n%s", got, want)
		}
	})

	t.Run("a change that has no place in the text is refused", func(t *testing.T) {
		// the word spans two lines, so the text does not contain it
		src := "ARG PKGS=\"a \\\n    b\"\nFROM scratch\n"
		root, err := imagebuilder.ParseDockerfile(strings.NewReader(src))
		if err != nil {
			t.Fatal(err)
		}
		root.Children[0].Next.Value = `PKGS="c"`
		if got, err := unparse([]byte(src), root); err == nil {
			t.Fatalf("unparse gave no error, but:\n%s", got)
		}
	})

	t.Run("a tree with another instruction is refused", func(t *testing.T) {
		src := "FROM scratch\nRUN true\n"
		root, err := imagebuilder.ParseDockerfile(strings.NewReader(src))
		if err != nil {
			t.Fatal(err)
		}
		root.Children[1].Value = "cmd"
		if got, err := unparse([]byte(src), root); err == nil {
			t.Fatalf("unparse gave no error, but:\n%s", got)
		}
	})
}

func TestBump(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file := filepath.Join(root.Name(), "Dockerfile")
	write := func(dockerfile string) {
		if err := os.WriteFile(file, []byte(tags(dockerfile)), 0644); err != nil {
			t.Fatal(err)
		}
	}
	read := func() string {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		return string(src)
	}

	t.Run("rewrites the Dockerfile", func(t *testing.T) {
		write("ARG IMG=lfedge/eve-alpine:OLD\nFROM ${IMG} AS build\n")
		if err := bump(root, "Dockerfile", alpine+":"+newTag); err != nil {
			t.Fatalf("bump: %v", err)
		}
		if got, want := read(), tags("ARG IMG=lfedge/eve-alpine:NEW\nFROM ${IMG} AS build\n"); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("does not touch a Dockerfile that has the tag", func(t *testing.T) {
		write("FROM lfedge/eve-alpine:NEW AS build\n")
		before := time.Now().Add(-time.Hour).Truncate(time.Second)
		if err := os.Chtimes(file, before, before); err != nil {
			t.Fatal(err)
		}
		if err := bump(root, "Dockerfile", alpine+":"+newTag); err != nil {
			t.Fatalf("bump: %v", err)
		}
		info, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		if !info.ModTime().Equal(before) {
			t.Fatalf("modified at %v, want %v", info.ModTime(), before)
		}
	})

	t.Run("leaves a Dockerfile alone that does not use the image", func(t *testing.T) {
		write("FROM scratch\nRUN echo lfedge/eve-alpine:OLD\n")
		if err := bump(root, "Dockerfile", alpine+":"+newTag); err == nil {
			t.Fatal("bump gave no error")
		}
		if got, want := read(), tags("FROM scratch\nRUN echo lfedge/eve-alpine:OLD\n"); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("wants an image with a tag", func(t *testing.T) {
		for _, ref := range []string{"lfedge/eve-alpine", "localhost:5000/eve-alpine", "lfedge/eve-alpine:", ":" + newTag} {
			write("FROM lfedge/eve-alpine:OLD\nFROM localhost:5000/eve-alpine:OLD\n")
			if err := bump(root, "Dockerfile", ref); err == nil {
				t.Errorf("bump(%q) gave no error", ref)
			}
			if got, want := read(), tags("FROM lfedge/eve-alpine:OLD\nFROM localhost:5000/eve-alpine:OLD\n"); got != want {
				t.Errorf("bump(%q): got %q, want %q", ref, got, want)
			}
		}
	})
}

// section returns what a description has under a heading, up to the next
// heading or to its end.
func section(body, heading string) string {
	_, after, found := strings.Cut(body, heading+"\n")
	if !found {
		return ""
	}
	if next := strings.Index(after, "\n#"); next >= 0 {
		after = after[:next+1]
	}
	return after
}

func TestFillPRBody(t *testing.T) {
	zstd := apk{Name: "zstd", Version: "1.6.0-r0", Checksum: "Q1zstd-160-r0"}
	gnutls := apk{Name: "gnutls", Version: "3.8.14-r0", Checksum: "Q1gnutls-3814-r0"}
	openssl := apk{Name: "openssl", Version: "3.5.9-r1", Checksum: "Q1openssl-359-r1"}

	t.Run("gives the template the names of the packages", func(t *testing.T) {
		got, err := fillPRBody("{{len .}} packages:{{range .}} {{.}}{{end}}.", []apk{gnutls, openssl, zstd})

		if err != nil {
			t.Fatalf("fillPRBody: %v", err)
		}
		if want := "3 packages: gnutls openssl zstd."; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("gives them in the order of the alphabet, and each one once", func(t *testing.T) {
		twice := apk{Name: "openssl", Version: "3.5.9-r0", Checksum: "Q1openssl-359-r0"}

		got, err := fillPRBody("{{range .}}<{{.}}>{{end}}", []apk{zstd, openssl, gnutls, twice, zstd})

		if err != nil {
			t.Fatalf("fillPRBody: %v", err)
		}
		if want := "<gnutls><openssl><zstd>"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("gives a template without packages nothing to list", func(t *testing.T) {
		got, err := fillPRBody("{{if .}}some{{else}}none{{end}}, {{len .}}", nil)

		if err != nil {
			t.Fatalf("fillPRBody: %v", err)
		}
		if want := "none, 0"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("takes names as they are", func(t *testing.T) {
		got, err := fillPRBody("{{range .}}{{.}}\n{{end}}", []apk{{Name: "libstdc++"}, {Name: "gtk+3.0"}, {Name: "so:libssl.so.3"}, {Name: "a<b>&c"}})

		if err != nil {
			t.Fatalf("fillPRBody: %v", err)
		}
		if want := "a<b>&c\ngtk+3.0\nlibstdc++\nso:libssl.so.3\n"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("returns text without anything to fill in as it is", func(t *testing.T) {
		got, err := fillPRBody("# Description\n\nBump the Alpine packages.\n", []apk{zstd})

		if err != nil {
			t.Fatalf("fillPRBody: %v", err)
		}
		if want := "# Description\n\nBump the Alpine packages.\n"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	for what, broken := range map[string]string{
		"a template that does not end":                     "## Changelog notes\n\n{{range .}}- {{.}}\n",
		"a template that asks for what a name has not":     "{{range .}}{{.Version}}{{end}}",
		"a template that asks for what a list has not":     "{{.Packages}}",
		"a template with a function that there is none of": "{{range .}}{{upper .}}{{end}}",
	} {
		t.Run("fails for "+what, func(t *testing.T) {
			got, err := fillPRBody(broken, []apk{zstd})

			if err == nil {
				t.Errorf("got %q and no error", got)
			}
			if got != "" {
				t.Errorf("got %q along with the error", got)
			}
		})
	}
}

func TestPRBody(t *testing.T) {
	const changelog = "## Changelog notes"

	t.Run("lists the packages in the changelog notes", func(t *testing.T) {
		body, err := fillPRBody(prBody, []apk{{Name: "zstd"}, {Name: "gnutls"}, {Name: "openssl"}})

		if err != nil {
			t.Fatalf("fillPRBody: %v", err)
		}
		want := `
Updated the Alpine Linux packages that EVE is built from and ships to their
current versions:

- gnutls
- openssl
- zstd

`
		if got := section(body, changelog); got != want {
			t.Errorf("the changelog notes are\n%q, want\n%q", got, want)
		}
	})

	t.Run("says it without a list if it knows of no packages", func(t *testing.T) {
		body, err := fillPRBody(prBody, nil)

		if err != nil {
			t.Fatalf("fillPRBody: %v", err)
		}
		want := `
Updated the Alpine Linux packages that EVE is built from and ships to their
current versions.

`
		if got := section(body, changelog); got != want {
			t.Errorf("the changelog notes are\n%q, want\n%q", got, want)
		}
	})

	t.Run("has the sections of the pull request template around them", func(t *testing.T) {
		body, err := fillPRBody(prBody, []apk{{Name: "zstd"}})

		if err != nil {
			t.Fatalf("fillPRBody: %v", err)
		}
		var headings []string
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, "#") {
				headings = append(headings, line)
			}
		}
		want := []string{"# Description", "## How to test and validate this PR", changelog, "## PR Backports", "## Checklist"}
		if strings.Join(headings, "|") != strings.Join(want, "|") {
			t.Errorf("the headings are %q, want %q", headings, want)
		}
		if strings.Contains(body, "{{") || strings.Contains(body, "}}") {
			t.Errorf("something is left to fill in:\n%s", body)
		}
		if !strings.HasSuffix(body, "check them.\n") {
			t.Errorf("the description ends with %q, want the end of the checklist", body[max(0, len(body)-40):])
		}
	})
}
