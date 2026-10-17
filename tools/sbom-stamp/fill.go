// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Content is what Stamp learns from the rest of the rootfs tar.
type Content struct {
	// SHA1 maps the hex SHA-256 of each regular file to its hex SHA-1.
	SHA1 map[string]string
	// Images maps a directory in the tar to the image linuxkit unpacked
	// there, taken from its LINUXKIT.source PAX record.
	Images map[string]string
}

const (
	alpine   = "Organization: Alpine Linux"
	linuxKit = "Organization: LinuxKit"
	// pkg/alpine/register-sbom-pkg.sh ends the description of every package
	// EVE builds from source with this.
	builtFromSource = "(built from source)"
)

// apkRelease matches the -r<N> release suffix of a package Alpine built.
var apkRelease = regexp.MustCompile(`-r[0-9]+$`)

// imageRef splits a reference such as docker.io/lfedge/eve-rngd:<tag> into
// registry, repository and tag or digest. ok is false for a LINUXKIT.source
// that names no image, such as linuxkit.volumes.
func imageRef(ref string) (registry, repo, version string, ok bool) {
	name := ref
	if i := strings.LastIndex(name, "@"); i >= 0 {
		name, version = name[:i], name[i+1:]
	}
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		if version == "" {
			version = name[i+1:]
		}
		name = name[:i]
	}
	registry, repo, found := strings.Cut(name, "/")
	if !found || version == "" {
		return "", "", "", false
	}
	if !strings.ContainsAny(registry, ".:") && registry != "localhost" {
		registry, repo = "docker.io", name
	}
	return registry, repo, version, true
}

func dockerPURL(registry, repo, version string) string {
	p := "pkg:docker/" + repo + "@" + strings.ReplaceAll(version, ":", "%3A")
	if registry != "docker.io" {
		p += "?repository_url=" + registry
	}
	return p
}

func imageSupplier(repo string) string {
	switch strings.SplitN(repo, "/", 2)[0] {
	case "lfedge":
		return lfEdge
	case "linuxkit":
		return linuxKit
	}
	return ""
}

type pkgInfo struct {
	SPDXID          string        `json:"SPDXID"`
	VersionInfo     string        `json:"versionInfo"`
	Supplier        string        `json:"supplier"`
	Description     string        `json:"description"`
	PackageFileName string        `json:"packageFileName"`
	ExternalRefs    []externalRef `json:"externalRefs"`
}

func (p pkgInfo) purl() string {
	for _, r := range p.ExternalRefs {
		if r.ReferenceType == "purl" {
			return r.ReferenceLocator
		}
	}
	return ""
}

// knownSupplier names the supplier of a package the scanner left without one,
// or returns "" when it cannot tell.
func knownSupplier(p pkgInfo) string {
	purl := p.purl()
	switch {
	case strings.HasSuffix(p.Description, builtFromSource),
		strings.HasPrefix(purl, "pkg:golang/github.com/lf-edge/"):
		return lfEdge
	// syft drops an apk maintainer it cannot parse, such as one whose email
	// domain has a hyphen (anchore/syft#5439), and gives some apk packages,
	// busybox among them, no purl.
	case (strings.HasPrefix(purl, "pkg:apk/") || strings.HasPrefix(p.SPDXID, "SPDXRef-Package-apk-")) &&
		apkRelease.MatchString(p.VersionInfo):
		return alpine
	}
	return ""
}

// fillPackage names and versions the root linuxkit makes for each image, and
// fills in suppliers the scanner left as NOASSERTION.
func fillPackage(raw json.RawMessage, o Options, c Content) (json.RawMessage, error) {
	var p pkgInfo
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	var po object
	if err := json.Unmarshal(raw, &po); err != nil {
		return nil, err
	}
	changed := false
	var err error
	set := func(key string, v any, after string) {
		if err == nil {
			po, err = po.set(key, v, after)
			changed = true
		}
	}
	supplier := p.Supplier
	if strings.HasPrefix(p.SPDXID, "SPDXRef-DocumentRoot-") {
		registry, repo, version, ok := imageRef(c.Images[p.PackageFileName])
		switch {
		case p.PackageFileName != "" && ok:
			set("name", repo, "")
			set("versionInfo", version, "name")
			set("externalRefs", []externalRef{{"PACKAGE-MANAGER", "purl", dockerPURL(registry, repo, version)}}, "")
			if s := imageSupplier(repo); s != "" {
				supplier = s
				set("supplier", s, "versionInfo")
			}
		case p.VersionInfo == "":
			// The images linuxkit unpacks at the top of the rootfs share
			// one root, which is part of this EVE-OS build.
			set("versionInfo", o.Version, "name")
			supplier = lfEdge
			set("supplier", lfEdge, "versionInfo")
		}
	}
	if supplier == "" || supplier == "NOASSERTION" {
		if s := knownSupplier(p); s != "" {
			set("supplier", s, "versionInfo")
		}
	}
	if err != nil || !changed {
		return raw, err
	}
	return json.Marshal(po)
}

type checksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// fillFile adds the SHA1 checksum SPDX 2.3 section 8.4 requires, looked up by
// the file's SHA256. It reports whether the file has a SHA1 afterwards.
func fillFile(raw json.RawMessage, c Content) (json.RawMessage, bool, error) {
	var f struct {
		Checksums []checksum `json:"checksums"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, false, err
	}
	var sum256 string
	for _, cs := range f.Checksums {
		switch cs.Algorithm {
		case "SHA1":
			return raw, true, nil
		case "SHA256":
			sum256 = cs.ChecksumValue
		}
	}
	sum1, ok := c.SHA1[sum256]
	if !ok {
		return raw, false, nil
	}
	var obj object
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, false, err
	}
	obj, err := obj.set("checksums", append(f.Checksums, checksum{"SHA1", sum1}), "")
	if err != nil {
		return nil, false, err
	}
	out, err := json.Marshal(obj)
	return out, true, err
}
