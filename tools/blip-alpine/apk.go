// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// apk is a package as the index of an Alpine repository describes it.
//
// The index is the file APKINDEX in the APKINDEX.tar.gz of a repository. It
// has a paragraph for every package, and in it a line for every field: a
// letter, a colon and the value, as in "P:openssl". The fields here are all
// that apk-tools writes into an index, in the order in which it writes
// them, each with its letter. Not every package has every line: of those
// of Alpine some have none for Maintainer, ProviderPriority, Depends,
// Provides or InstallIf. A field without a line is empty.
type apk struct {
	// Checksum (C) is the hash of the metadata of the package, Q1 and a
	// SHA-1 in base64, as in Q12Br74iU//OiFef7ymUeeYSJPiGc=. It is the same
	// wherever the same package is, and another one for another build of
	// the same version.
	Checksum string
	// Name (P) is the name of the package, as in openssl.
	Name string
	// Version (V) is its version, as in 3.5.9-r1.
	Version string
	// Arch (A) is the architecture that it is built for, as in x86_64.
	Arch string
	// FileSize (S) is the size of the .apk file in bytes.
	FileSize int64
	// InstalledSize (I) is an estimate of the size of what the package
	// installs, in bytes.
	InstalledSize int64
	// Description (T) says in one line what the package is.
	Description string
	// URL (U) is the website of what is packaged.
	URL string
	// License (L) is the license, mostly as an SPDX expression like
	// Apache-2.0.
	License string
	// Origin (o) is the source package that it is built from. Packages that
	// are built together share it: openssl, libssl3 and libcrypto3 all have
	// openssl.
	Origin string
	// Maintainer (m) is the name and the e-mail address of who maintains
	// the package.
	Maintainer string
	// BuildTime (t) is when the package was built, in the index as seconds
	// since 1970.
	BuildTime time.Time
	// Commit (c) is the commit of the repository of build recipes, for
	// Alpine that is aports, which the package was built from.
	Commit string
	// ProviderPriority (k) decides between packages that provide the same
	// name without a version: the one with the highest is installed, as
	// busybox-binsh with 100 is for /bin/sh and not dash-binsh with 60. It
	// is 0 for a package that is not to be chosen that way.
	ProviderPriority int
	// Depends (D) is what has to be installed for the package: names of
	// packages or names that packages provide, like so:libssl.so.3, some
	// with the version that it has to be, as in libssl3=3.5.9-r1 or
	// fortify-headers>=1.1-r2. One with a ! in front must not be installed
	// with it.
	Depends []string
	// Provides (p) is what the package can be asked for by besides its
	// name, mostly with a version: its programs as in
	// cmd:openssl=3.5.9-r1, its libraries as in so:libssl.so.3=3, or a
	// name like /bin/sh.
	Provides []string
	// InstallIf (i) makes the package get installed without being asked
	// for, once all that is listed here is installed: openssl-doc has docs
	// and openssl=3.5.9-r1.
	InstallIf []string
}

// parseAPKINDEX returns the packages of the index of an Alpine repository,
// in the order of the index. It reads the index the way a repository has
// it, as an APKINDEX.tar.gz, or as the file APKINDEX that is in there. The
// signature of an APKINDEX.tar.gz is not checked.
//
// Lines of a kind that the type apk has no field for are skipped, so that
// an index can still be read when a later apk writes more into it.
func parseAPKINDEX(r io.Reader) ([]apk, error) {
	index := bufio.NewReader(r)
	start, err := index.Peek(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	// two bytes that every gzip stream starts with, and no line of an index
	if bytes.Equal(start, []byte{0x1f, 0x8b}) {
		unzipped, err := gzip.NewReader(index)
		if err != nil {
			return nil, err
		}
		archive := tar.NewReader(unzipped)
		for {
			header, err := archive.Next()
			if errors.Is(err, io.EOF) {
				return nil, errors.New("no file APKINDEX in the archive")
			}
			if err != nil {
				return nil, err
			}
			if header.Name == "APKINDEX" {
				break
			}
		}
		index = bufio.NewReader(archive)
	}

	var packages []apk
	var pkg *apk // of the paragraph that is being read
	for number := 1; ; number++ {
		line, err := index.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		last := err != nil
		line = strings.TrimSuffix(line, "\n")
		if line != "" {
			if pkg == nil {
				pkg = &apk{}
			}
			if err := pkg.set(line); err != nil {
				return nil, fmt.Errorf("line %d of the index: %w", number, err)
			}
		}
		if pkg != nil && (line == "" || last) {
			if pkg.Name == "" {
				return nil, fmt.Errorf("line %d of the index: the package that ends here has no name", number)
			}
			packages = append(packages, *pkg)
			pkg = nil
		}
		if last {
			return packages, nil
		}
	}
}

// set gives the package what a line of an index says of it.
func (a *apk) set(line string) error {
	if len(line) < 2 || line[1] != ':' {
		return fmt.Errorf("%.40q is not a letter, a colon and a value", line)
	}
	value := line[2:]
	var noNumber error
	// number returns the value as a number: digits only, and no more than
	// an int64 holds
	number := func() int64 {
		var n uint64
		n, noNumber = strconv.ParseUint(value, 10, 63)
		return int64(n)
	}
	switch line[0] {
	case 'C':
		a.Checksum = value
	case 'P':
		a.Name = value
	case 'V':
		a.Version = value
	case 'A':
		a.Arch = value
	case 'S':
		a.FileSize = number()
	case 'I':
		a.InstalledSize = number()
	case 'T':
		a.Description = value
	case 'U':
		a.URL = value
	case 'L':
		a.License = value
	case 'o':
		a.Origin = value
	case 'm':
		a.Maintainer = value
	case 't':
		a.BuildTime = time.Unix(number(), 0).UTC()
	case 'c':
		a.Commit = value
	case 'k':
		a.ProviderPriority = int(number())
	case 'D':
		a.Depends = strings.Fields(value)
	case 'p':
		a.Provides = strings.Fields(value)
	case 'i':
		a.InstallIf = strings.Fields(value)
	}
	if noNumber != nil {
		return fmt.Errorf("%.40q has no number that fits there", line)
	}
	return nil
}

// compareApks returns the packages in which two lists of packages differ,
// as b has them and in the order of b: with the lists the other way around
// it returns them as a has them. It returns none if the lists agree in the
// packages that both of them have.
//
// Packages are told apart by their names, and a package is the same in
// both lists if it has the same checksum. A package that only one of the
// lists has makes no difference.
//
// A list may have a name more than once: the index of the mirror of
// eve-alpine has every version of a package that the mirror ever got, where
// a repository of Alpine has the current one. The lists agree in such a
// package if one of its checksums is in both of them, and if they do not,
// all that b has of that name is returned.
func compareApks(a, b []apk) []apk {
	checksums := map[string][]string{} // of a, by name
	for _, p := range a {
		checksums[p.Name] = append(checksums[p.Name], p.Checksum)
	}
	same := map[string]bool{} // by name, of the packages that both have
	for _, p := range b {
		if ofA, both := checksums[p.Name]; both {
			same[p.Name] = same[p.Name] || slices.Contains(ofA, p.Checksum)
		}
	}
	var differ []apk
	for _, p := range b {
		if is, both := same[p.Name]; both && !is {
			differ = append(differ, p)
		}
	}
	return differ
}

// apkMirror is a mirror of packages of Alpine that an eve-alpine image has.
type apkMirror struct {
	// Version is the version of Alpine that the packages are of, as in
	// 3.22, or edge.
	Version string
	// Arch is the architecture that they are for, as apk names it: x86_64.
	Arch string
	// Index is where the image has the index of the mirror, an
	// APKINDEX.tar.gz.
	Index string
}

// apkMirrors returns the mirrors of an eve-alpine image. The image says
// where they are, because it installs its packages from them: in its
// /etc/apk/repositories it has a line like /mirror/3.22/x86_64/.. for each,
// and an image of a version of EVE that takes packages of Alpine edge too
// has two of them.
func apkMirrors(imageName string) ([]apkMirror, error) {
	const repositories = "/etc/apk/repositories"
	file, err := extractFromDockerImage(imageName, repositories)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	lines, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var mirrors []apkMirror
	for _, line := range strings.Fields(string(lines)) {
		// apk looks for the index in the directory of its architecture
		// below a repository, which is where the .. comes from
		packages, isMirror := strings.CutSuffix(line, "/..")
		version := path.Dir(packages)
		if !isMirror || !path.IsAbs(line) || path.Dir(version) == "/" {
			return nil, fmt.Errorf("%s of %s: %q is no mirror in the image", repositories, imageName, line)
		}
		mirrors = append(mirrors, apkMirror{
			Version: path.Base(version),
			Arch:    path.Base(packages),
			Index:   path.Join(packages, "APKINDEX.tar.gz"),
		})
	}
	if len(mirrors) == 0 {
		return nil, fmt.Errorf("%s of %s names no mirror", repositories, imageName)
	}
	return mirrors, nil
}

// upstreamIndex returns where Alpine has the index of a repository like
// main or community for the version and the architecture of the mirror.
func (m apkMirror) upstreamIndex(repository string) string {
	version := m.Version
	if version != "edge" {
		version = "v" + version
	}
	return "https://dl-cdn.alpinelinux.org/alpine/" + path.Join(version, repository, m.Arch, "APKINDEX.tar.gz")
}

// apkRepositories returns the repositories of a version of Alpine that
// eve-alpine mirrors packages of, as the checkout of EVE at root has it:
// pkg/alpine has a list of packages for each, mirrors/3.22/main for main of
// Alpine 3.22. A list like main.x86_64 is what one architecture gets on top
// of that.
func apkRepositories(root *os.Root, version string) ([]string, error) {
	// one directory, and not one that is somewhere else
	if !fs.ValidPath(version) || version == "." || strings.Contains(version, "/") {
		return nil, fmt.Errorf("%q is no version of Alpine", version)
	}
	lists, err := fs.ReadDir(root.FS(), path.Join("pkg/alpine/mirrors", version))
	if err != nil {
		return nil, err
	}
	var repositories []string
	for _, list := range lists {
		if !list.IsDir() && !strings.Contains(list.Name(), ".") {
			repositories = append(repositories, list.Name())
		}
	}
	return repositories, nil
}
