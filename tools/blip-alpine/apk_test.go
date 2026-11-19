// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

// names returns the names of the packages.
func names(packages []apk) []string {
	var all []string
	for _, p := range packages {
		all = append(all, p.Name)
	}
	return all
}

// apkindexTarGz returns an APKINDEX.tar.gz as a repository has it: two gzip
// streams that are one tar archive together, of which the first has the
// signature and the second has the files with these names and contents.
func apkindexTarGz(t *testing.T, files ...[2]string) []byte {
	t.Helper()
	var archive bytes.Buffer
	stream := func(end bool, files ...[2]string) {
		zipped := gzip.NewWriter(&archive)
		w := tar.NewWriter(zipped)
		for _, file := range files {
			header := &tar.Header{Typeflag: tar.TypeReg, Name: file[0], Mode: 0644, Size: int64(len(file[1]))}
			if err := w.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(w, file[1]); err != nil {
				t.Fatal(err)
			}
		}
		// the signature is an archive without an end, so that the files
		// follow as more of the same archive
		finish := w.Flush
		if end {
			finish = w.Close
		}
		if err := finish(); err != nil {
			t.Fatal(err)
		}
		if err := zipped.Close(); err != nil {
			t.Fatal(err)
		}
	}
	stream(false, [2]string{".SIGN.RSA.alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub", strings.Repeat("\x5a", 512)})
	stream(true, files...)
	return archive.Bytes()
}

func TestParseAPKINDEX(t *testing.T) {
	t.Run("gives every field of a package what its line says", func(t *testing.T) {
		index := `C:Q12Br74iU//OiFef7ymUeeYSJPiGc=
P:openssl
V:3.5.9-r1
A:x86_64
S:340923
I:820320
T:Toolkit for Transport Layer Security (TLS)
U:https://www.openssl.org/
L:Apache-2.0
o:openssl-src
m:Eve Maintainer <eve@example.org>
t:1767225600
c:c25a43863aa0cd4b870c0045e837acafcc661950
k:100
D:libssl3=3.5.9-r1 so:libc.musl-x86_64.so.1 !libressl
p:openssl3=3.5.9-r1 cmd:openssl=3.5.9-r1
i:docs openssl-doc=3.5.9-r1

`

		got, err := parseAPKINDEX(strings.NewReader(index))

		if err != nil {
			t.Fatalf("parseAPKINDEX: %v", err)
		}
		want := []apk{{
			Checksum:         "Q12Br74iU//OiFef7ymUeeYSJPiGc=",
			Name:             "openssl",
			Version:          "3.5.9-r1",
			Arch:             "x86_64",
			FileSize:         340923,
			InstalledSize:    820320,
			Description:      "Toolkit for Transport Layer Security (TLS)",
			URL:              "https://www.openssl.org/",
			License:          "Apache-2.0",
			Origin:           "openssl-src",
			Maintainer:       "Eve Maintainer <eve@example.org>",
			BuildTime:        time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
			Commit:           "c25a43863aa0cd4b870c0045e837acafcc661950",
			ProviderPriority: 100,
			Depends:          []string{"libssl3=3.5.9-r1", "so:libc.musl-x86_64.so.1", "!libressl"},
			Provides:         []string{"openssl3=3.5.9-r1", "cmd:openssl=3.5.9-r1"},
			InstallIf:        []string{"docs", "openssl-doc=3.5.9-r1"},
		}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got\n%+v, want\n%+v", got, want)
		}
	})

	t.Run("leaves a field empty that a package has no line for", func(t *testing.T) {
		index := "P:alpine-baselayout-data\nV:3.7.0-r0\n\n"

		got, err := parseAPKINDEX(strings.NewReader(index))

		if err != nil {
			t.Fatalf("parseAPKINDEX: %v", err)
		}
		want := []apk{{Name: "alpine-baselayout-data", Version: "3.7.0-r0"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got\n%+v, want\n%+v", got, want)
		}
	})

	t.Run("takes a value as it is, with its colons and spaces", func(t *testing.T) {
		index := "P:busybox\nT:Size optimized toolbox: many  common UNIX utilities \nU:https://busybox.net:443/a:b\nL:GPL-2.0-only AND MIT\n\n"

		got, err := parseAPKINDEX(strings.NewReader(index))

		if err != nil {
			t.Fatalf("parseAPKINDEX: %v", err)
		}
		want := []apk{{
			Name:        "busybox",
			Description: "Size optimized toolbox: many  common UNIX utilities ",
			URL:         "https://busybox.net:443/a:b",
			License:     "GPL-2.0-only AND MIT",
		}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got\n%+v, want\n%+v", got, want)
		}
	})

	// The packages of an index are paragraphs: an empty line is between
	// them, and in the indexes of Alpine after the last one too.
	paragraphs := []struct {
		what  string
		index string
		want  []string
	}{
		{"an index as Alpine has it", "P:musl\nV:1.2.5-r10\n\nP:busybox\nV:1.37.0-r20\n\nP:zstd\nV:1.6.0-r0\n\n", []string{"musl", "busybox", "zstd"}},
		{"one that ends with its last line", "P:musl\nV:1.2.5-r10\n\nP:busybox\nV:1.37.0-r20\n", []string{"musl", "busybox"}},
		{"one that ends in the middle of a line", "P:musl\nV:1.2.5-r10\n\nP:busybox", []string{"musl", "busybox"}},
		{"one with more empty lines than needed", "\n\nP:musl\n\n\n\nP:busybox\n\n\n", []string{"musl", "busybox"}},
		{"one with a single package", "P:musl\n", []string{"musl"}},
		{"one of a repository without packages", "", nil},
		{"one of nothing but empty lines", "\n\n\n", nil},
	}
	for _, p := range paragraphs {
		t.Run("returns the packages in their order of "+p.what, func(t *testing.T) {
			got, err := parseAPKINDEX(strings.NewReader(p.index))

			if err != nil {
				t.Fatalf("parseAPKINDEX: %v", err)
			}
			if !slices.Equal(names(got), p.want) {
				t.Errorf("got the packages %q, want %q", names(got), p.want)
			}
		})
	}

	t.Run("skips lines of a kind that it does not know", func(t *testing.T) {
		index := "P:openssl\nr:libressl\nV:3.5.9-r1\nX:of a later version\nz:\n\nP:musl\n\n"

		got, err := parseAPKINDEX(strings.NewReader(index))

		if err != nil {
			t.Fatalf("parseAPKINDEX: %v", err)
		}
		want := []apk{{Name: "openssl", Version: "3.5.9-r1"}, {Name: "musl"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got\n%+v, want\n%+v", got, want)
		}
	})

	t.Run("reads a line of any length", func(t *testing.T) {
		// more than the 64 kB that a line may have for bufio.Scanner
		index := "P:texlive-full\nD:" + strings.Repeat("texmf-dist-fontsextra ", 5000) + "\nV:20250308-r0\n\n"

		got, err := parseAPKINDEX(strings.NewReader(index))

		if err != nil {
			t.Fatalf("parseAPKINDEX: %v", err)
		}
		if len(got) != 1 || len(got[0].Depends) != 5000 || got[0].Version != "20250308-r0" {
			t.Errorf("got %d packages, want one with 5000 dependencies and the version 20250308-r0", len(got))
		}
	})

	// What is wrong with an index is said with the line that it is in.
	wrong := []struct {
		what  string
		index string
		line  string
	}{
		{"a line that is no field", "P:musl\nV:1.2.5-r10\n\nv3.22.8-71-gb9dd54c5494\n", "line 4"},
		{"a line of one letter", "P:musl\nV\n", "line 2"},
		{"a line without a letter", "P:musl\n:1.2.5-r10\n", "line 2"},
		{"a file size that is no number", "P:musl\nS:big\n\n", "line 2"},
		{"an installed size below zero", "P:musl\nV:1.2.5-r10\nI:-1\n\n", "line 3"},
		{"a build time that is no number", "P:musl\n\nP:zstd\nt:2026-01-01\n\n", "line 4"},
		{"a provider priority that is no whole number", "k:1.5\nP:musl\n\n", "line 1"},
		{"a number without digits", "P:musl\nS:\n\n", "line 2"},
		{"a number that is too large to be one", "P:musl\nV:1.2.5-r10\n\nP:zstd\nV:1.6.0-r0\nI:9223372036854775808\n\n", "line 6"},
		{"a package without a name", "P:musl\n\nV:1.2.5-r10\nA:x86_64\n\nP:zstd\n\n", "line 5"},
		{"a package without a name at the end", "P:musl\n\nV:1.2.5-r10", "line 3"},
	}
	for _, w := range wrong {
		t.Run("fails for "+w.what, func(t *testing.T) {
			got, err := parseAPKINDEX(strings.NewReader(w.index))

			if err == nil || !strings.Contains(err.Error(), w.line) {
				t.Errorf("got error %v, want one that names %s", err, w.line)
			}
			if got != nil {
				t.Errorf("got the packages %q along with the error", names(got))
			}
		})
	}

	t.Run("does not return the part of an index that it could read", func(t *testing.T) {
		broken := errors.New("connection reset by peer")
		index := io.MultiReader(strings.NewReader("P:musl\nV:1.2.5-r10\n\nP:busybox\nV:1.37"), iotest.ErrReader(broken))

		got, err := parseAPKINDEX(index)

		if !errors.Is(err, broken) {
			t.Errorf("got error %v, want the one of reading", err)
		}
		if got != nil {
			t.Errorf("got the packages %q along with the error", names(got))
		}
	})

	t.Run("reads the index out of an APKINDEX.tar.gz", func(t *testing.T) {
		archive := apkindexTarGz(t,
			[2]string{"DESCRIPTION", "v3.22.8-71-gb9dd54c5494\n"},
			[2]string{"APKINDEX", "P:musl\nV:1.2.5-r10\n\nP:busybox\nV:1.37.0-r20\n\n"},
		)

		got, err := parseAPKINDEX(bytes.NewReader(archive))

		if err != nil {
			t.Fatalf("parseAPKINDEX: %v", err)
		}
		want := []apk{{Name: "musl", Version: "1.2.5-r10"}, {Name: "busybox", Version: "1.37.0-r20"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got\n%+v, want\n%+v", got, want)
		}
	})

	t.Run("fails for an archive without an APKINDEX", func(t *testing.T) {
		archive := apkindexTarGz(t,
			[2]string{"DESCRIPTION", "v3.22.8-71-gb9dd54c5494\n"},
			[2]string{"APKINDEX.old", "P:musl\nV:1.2.5-r10\n\n"},
		)

		got, err := parseAPKINDEX(bytes.NewReader(archive))

		if err == nil || !strings.Contains(err.Error(), "APKINDEX") {
			t.Errorf("got error %v, want one that says that there is no APKINDEX", err)
		}
		if got != nil {
			t.Errorf("got the packages %q along with the error", names(got))
		}
	})

	t.Run("fails for an archive that ends too early", func(t *testing.T) {
		archive := apkindexTarGz(t,
			[2]string{"DESCRIPTION", "v3.22.8-71-gb9dd54c5494\n"},
			[2]string{"APKINDEX", "P:musl\nV:1.2.5-r10\n\n" + strings.Repeat("P:busybox\nV:1.37.0-r20\nT:"+strings.Repeat("x", 1000)+"\n\n", 100)},
		)

		got, err := parseAPKINDEX(bytes.NewReader(archive[:len(archive)-64]))

		if err == nil {
			t.Errorf("got no error for an archive that lacks its end")
		}
		if got != nil {
			t.Errorf("got %d packages along with the error", len(got))
		}
	})
}

func TestCompareApks(t *testing.T) {
	musl := apk{Name: "musl", Version: "1.2.5-r13", Checksum: "Q1musl-125-r13"}
	busybox := apk{Name: "busybox", Version: "1.37.0-r20", Checksum: "Q1busybox-1370-r20"}
	zstd156 := apk{Name: "zstd", Version: "1.5.6-r2", Checksum: "Q1zstd-156-r2"}
	zstd157 := apk{Name: "zstd", Version: "1.5.7-r0", Checksum: "Q1zstd-157-r0"}
	zstd160 := apk{Name: "zstd", Version: "1.6.0-r0", Checksum: "Q1zstd-160-r0"}
	openssl356 := apk{Name: "openssl", Version: "3.5.6-r0", Checksum: "Q1openssl-356-r0"}
	openssl359 := apk{Name: "openssl", Version: "3.5.9-r1", Checksum: "Q1openssl-359-r1"}
	built := apk{Name: "zstd", Version: "1.6.0-r0", Checksum: "Q1zstd-160-r0"}
	builtAgain := apk{Name: "zstd", Version: "1.6.0-r0", Checksum: "Q1zstd-160-r0-again"}
	libsOne := apk{Name: "zstd-libs", Checksum: "Q1one"}
	libsOther := apk{Name: "zstd-libs", Checksum: "Q1zstd-160-r0"}

	// ofB is what differs of b, and ofA what differs of a, which is what
	// comes of the lists the other way around.
	cases := []struct {
		what     string
		a, b     []apk
		ofB, ofA []apk
	}{
		{"the same packages", []apk{musl, busybox}, []apk{musl, busybox}, nil, nil},
		{"the same packages in another order", []apk{musl, busybox, zstd160}, []apk{zstd160, musl, busybox}, nil, nil},
		{"no packages", nil, nil, nil, nil},
		{"packages in one of them only", []apk{musl, busybox}, nil, nil, nil},
		{"no package that both have", []apk{musl}, []apk{busybox, zstd160}, nil, nil},
		{"a package that both have among others", []apk{musl, busybox}, []apk{busybox, zstd160}, nil, nil},

		{"a package with another checksum", []apk{zstd157}, []apk{zstd160}, []apk{zstd160}, []apk{zstd157}},
		{
			"a package with another checksum after the same ones",
			[]apk{musl, busybox, zstd157}, []apk{musl, busybox, zstd160},
			[]apk{zstd160}, []apk{zstd157},
		},
		{
			"a package with another checksum before the same ones",
			[]apk{zstd157, musl, busybox}, []apk{zstd160, musl, busybox},
			[]apk{zstd160}, []apk{zstd157},
		},
		{
			"a package with another checksum among those that only one has",
			[]apk{musl, zstd157}, []apk{busybox, zstd160},
			[]apk{zstd160}, []apk{zstd157},
		},
		{
			"more than one package with another checksum, in the order of the list",
			[]apk{openssl356, musl, zstd157}, []apk{zstd160, busybox, musl, openssl359},
			[]apk{zstd160, openssl359}, []apk{openssl356, zstd157},
		},
		{"a version that was built again", []apk{built}, []apk{builtAgain}, []apk{builtAgain}, []apk{built}},
		{
			"a package with the same checksum, whatever else they say of it",
			[]apk{{Name: "zstd", Version: "1.6.0-r0", Checksum: "Q1zstd-160-r0", FileSize: 123, Description: "Zstandard"}},
			[]apk{{Name: "zstd", Version: "1.6.0", Checksum: "Q1zstd-160-r0", FileSize: 456, Depends: []string{"musl"}}},
			nil, nil,
		},
		{
			"the same checksum under another name",
			[]apk{zstd160, libsOne}, []apk{libsOther},
			[]apk{libsOther}, []apk{libsOne},
		},

		// The mirror of eve-alpine keeps every version of a package that
		// it ever had, where a repository of Alpine has the current one.
		{"an old version next to the one that both have", []apk{zstd156, zstd157, zstd160}, []apk{zstd160}, nil, nil},
		{"old versions after the one that both have", []apk{zstd160, zstd156, zstd157}, []apk{zstd160}, nil, nil},
		{"old versions around the one that both have", []apk{zstd156, zstd160, zstd157}, []apk{zstd160}, nil, nil},
		{"only old versions of a package", []apk{zstd156, zstd157}, []apk{zstd160}, []apk{zstd160}, []apk{zstd156, zstd157}},
		{"several versions in both, one of them the same", []apk{zstd156, zstd157}, []apk{zstd157, zstd160}, nil, nil},
		{
			"several versions in both, none of them the same",
			[]apk{zstd156, openssl359}, []apk{zstd157, zstd160, openssl359},
			[]apk{zstd157, zstd160}, []apk{zstd156},
		},
		{
			"one package with its current version and one without",
			[]apk{zstd157, zstd160, openssl356, musl}, []apk{musl, zstd160, openssl359, busybox},
			[]apk{openssl359}, []apk{openssl356},
		},
		{
			"every package with its current version among old ones",
			[]apk{zstd157, zstd160, openssl356, openssl359, musl}, []apk{musl, zstd160, openssl359, busybox},
			nil, nil,
		},
	}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			if got := compareApks(c.a, c.b); !reflect.DeepEqual(got, c.ofB) {
				t.Errorf("got\n%+v, want\n%+v", got, c.ofB)
			}
			if got := compareApks(c.b, c.a); !reflect.DeepEqual(got, c.ofA) {
				t.Errorf("the other way around: got\n%+v, want\n%+v", got, c.ofA)
			}
		})
	}
}

func TestApkMirrors(t *testing.T) {
	// repositories puts an image into a registry that has this as its
	// /etc/apk/repositories, and returns the name of the image.
	repositories := func(t *testing.T, content string) string {
		reg := newFakeRegistry(t)
		return reg.tag("lfedge/eve-alpine", "3a8c6b27", reg.image("lfedge/eve-alpine", "amd64", layerOf(t,
			directory("etc/"),
			regular("etc/alpine-release", "3.22.8\n"),
			directory("etc/apk/"),
			regular("etc/apk/repositories", content),
			regular("etc/apk/repositories.upstream", "https://dl-cdn.alpinelinux.org/alpine/v3.22/main\n"),
			directory("mirror/"),
		)))
	}

	cases := []struct {
		what    string
		content string
		want    []apkMirror
	}{
		{
			"the mirror of an image of today",
			"/mirror/3.22/x86_64/..\n",
			[]apkMirror{{Version: "3.22", Arch: "x86_64", Index: "/mirror/3.22/x86_64/APKINDEX.tar.gz"}},
		},
		{
			"both mirrors of an image that has one of Alpine edge too",
			"/mirror/3.16/x86_64/..\n/mirror/edge/x86_64/..\n",
			[]apkMirror{
				{Version: "3.16", Arch: "x86_64", Index: "/mirror/3.16/x86_64/APKINDEX.tar.gz"},
				{Version: "edge", Arch: "x86_64", Index: "/mirror/edge/x86_64/APKINDEX.tar.gz"},
			},
		},
		{
			"the mirror of an image for another architecture",
			"/mirror/3.22/aarch64/..\n",
			[]apkMirror{{Version: "3.22", Arch: "aarch64", Index: "/mirror/3.22/aarch64/APKINDEX.tar.gz"}},
		},
		{
			"a mirror whose line has no end",
			"/mirror/3.22/riscv64/..",
			[]apkMirror{{Version: "3.22", Arch: "riscv64", Index: "/mirror/3.22/riscv64/APKINDEX.tar.gz"}},
		},
	}
	for _, c := range cases {
		t.Run("returns "+c.what, func(t *testing.T) {
			got, err := apkMirrors(repositories(t, c.content))

			if err != nil {
				t.Fatalf("apkMirrors: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got\n%+v, want\n%+v", got, c.want)
			}
		})
	}

	// An image that does not install from a mirror of its own is not one
	// of eve-alpine.
	wrong := map[string]string{
		"repositories on the network, as Alpine has them": "https://dl-cdn.alpinelinux.org/alpine/v3.22/main\nhttps://dl-cdn.alpinelinux.org/alpine/v3.22/community\n",
		"a mirror next to a repository on the network":    "/mirror/3.22/x86_64/..\nhttps://dl-cdn.alpinelinux.org/alpine/v3.22/community\n",
		"a directory that is not the one above packages":  "/mirror/3.22/x86_64\n",
		"a line that is too short for a mirror":           "/x86_64/..\n",
		"a repository on the network that ends like one":  "https://dl-cdn.alpinelinux.org/alpine/v3.22/x86_64/..\n",
		"no repositories": "\n",
	}
	for what, content := range wrong {
		t.Run("fails for "+what, func(t *testing.T) {
			got, err := apkMirrors(repositories(t, content))

			if err == nil {
				t.Errorf("got %+v and no error", got)
			}
		})
	}

	t.Run("fails for an image without /etc/apk/repositories", func(t *testing.T) {
		reg := newFakeRegistry(t)
		image := reg.tag("lfedge/eve-alpine", "3.22", reg.image("lfedge/eve-alpine", "amd64", layerOf(t,
			directory("etc/"), regular("etc/alpine-release", "3.22.8\n"),
		)))

		got, err := apkMirrors(image)

		if err == nil || !strings.Contains(err.Error(), "/etc/apk/repositories") {
			t.Errorf("got %+v and error %v, want an error that names /etc/apk/repositories", got, err)
		}
	})
}

func TestApkMirrorUpstreamIndex(t *testing.T) {
	cases := []struct {
		mirror     apkMirror
		repository string
		want       string
	}{
		{apkMirror{Version: "3.22", Arch: "x86_64"}, "main", "https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/APKINDEX.tar.gz"},
		{apkMirror{Version: "3.22", Arch: "aarch64"}, "community", "https://dl-cdn.alpinelinux.org/alpine/v3.22/community/aarch64/APKINDEX.tar.gz"},
		{apkMirror{Version: "3.16", Arch: "riscv64"}, "testing", "https://dl-cdn.alpinelinux.org/alpine/v3.16/testing/riscv64/APKINDEX.tar.gz"},
		{apkMirror{Version: "edge", Arch: "x86_64"}, "community", "https://dl-cdn.alpinelinux.org/alpine/edge/community/x86_64/APKINDEX.tar.gz"},
	}
	for _, c := range cases {
		if got := c.mirror.upstreamIndex(c.repository); got != c.want {
			t.Errorf("%s of Alpine %s for %s: got %s, want %s", c.repository, c.mirror.Version, c.mirror.Arch, got, c.want)
		}
	}
}

func TestApkRepositories(t *testing.T) {
	// checkout makes a directory with the files as a checkout of EVE has
	// them, and returns it the way openRoot does.
	checkout := func(t *testing.T, files ...string) *os.Root {
		dir := t.TempDir()
		for _, file := range files {
			path := filepath.Join(dir, filepath.FromSlash(file))
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("musl\nbusybox\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { root.Close() })
		return root
	}

	t.Run("returns the repositories that pkg/alpine has a list of packages for", func(t *testing.T) {
		root := checkout(t,
			"pkg/alpine/Dockerfile",
			"pkg/alpine/mirrors/3.22/main",
			"pkg/alpine/mirrors/3.22/main.x86_64",
			"pkg/alpine/mirrors/3.22/main.aarch64",
			"pkg/alpine/mirrors/3.22/community",
			"pkg/alpine/mirrors/3.22/community.x86_64",
		)

		got, err := apkRepositories(root, "3.22")

		if err != nil {
			t.Fatalf("apkRepositories: %v", err)
		}
		if want := []string{"community", "main"}; !slices.Equal(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("returns those of the version that is asked for", func(t *testing.T) {
		root := checkout(t,
			"pkg/alpine/mirrors/3.16/main",
			"pkg/alpine/mirrors/3.16/main.x86_64",
			"pkg/alpine/mirrors/3.16/community",
			"pkg/alpine/mirrors/edge/community",
			"pkg/alpine/mirrors/edge/testing",
		)

		for version, want := range map[string][]string{"3.16": {"community", "main"}, "edge": {"community", "testing"}} {
			got, err := apkRepositories(root, version)

			if err != nil {
				t.Fatalf("apkRepositories: %v", err)
			}
			if !slices.Equal(got, want) {
				t.Errorf("%s: got %q, want %q", version, got, want)
			}
		}
	})

	t.Run("leaves out a repository that has a list for one architecture only", func(t *testing.T) {
		// pkg/alpine/Dockerfile skips such a repository too
		root := checkout(t, "pkg/alpine/mirrors/3.22/main", "pkg/alpine/mirrors/3.22/testing.aarch64")

		got, err := apkRepositories(root, "3.22")

		if err != nil {
			t.Fatalf("apkRepositories: %v", err)
		}
		if want := []string{"main"}; !slices.Equal(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	for what, version := range map[string]string{
		"a version that pkg/alpine does not mirror": "3.16",
		"a version that leads out of pkg/alpine":    "../../../pkg/alpine/mirrors/3.22",
		"no version":                                "",
	} {
		t.Run("fails for "+what, func(t *testing.T) {
			root := checkout(t, "pkg/alpine/mirrors/3.22/main", "pkg/alpine/mirrors/3.22/community")

			got, err := apkRepositories(root, version)

			if err == nil {
				t.Errorf("got %q and no error", got)
			}
		})
	}
}
