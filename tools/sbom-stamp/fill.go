// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"path"
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
	// Paths maps each path in the tar to the hex SHA-256 of the last
	// regular file written there, or to "" for any other entry type. A nil
	// Paths leaves files whose content is not in the tar untouched.
	Paths map[string]string
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
	Name            string        `json:"name"`
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

// purlEscape percent-encodes s as a purl name or version: everything but
// letters, digits, ".-_~" and ":" (purl-spec clause 5.4).
func purlEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9',
			strings.IndexByte(".-_~:", c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// sourcePURL is the purl of a package EVE builds from source. The scanner
// labels it pkg:apk because register-sbom-pkg.sh records it in the apk
// database, which would match it against the distro's package of the same
// name. purl-spec defines the generic type for upstream-from-distro packages.
func sourcePURL(p pkgInfo) string {
	purl := "pkg:generic/" + purlEscape(p.Name)
	if p.VersionInfo != "" {
		purl += "@" + purlEscape(p.VersionInfo)
	}
	return purl
}

// withPURL replaces the purl in refs, or adds one, keeping the other refs.
func withPURL(refs []externalRef, purl string) []externalRef {
	out := []externalRef{}
	added := false
	for _, r := range refs {
		if r.ReferenceType == "purl" {
			if added {
				continue
			}
			r.ReferenceLocator, added = purl, true
		}
		out = append(out, r)
	}
	if !added {
		out = append(out, externalRef{"PACKAGE-MANAGER", "purl", purl})
	}
	return out
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
	if strings.HasSuffix(p.Description, builtFromSource) {
		if purl := sourcePURL(p); purl != p.purl() {
			set("externalRefs", withPURL(p.ExternalRefs, purl), "")
		}
	}
	if err != nil || !changed {
		return raw, err
	}
	return json.Marshal(po)
}

// fillPURLs gives a package without a purl the purl of the other copies of
// it, the copies that share its SPDXID, name and version, when they all agree
// on one. linuxkit's merge keeps one copy per image, and the scanner leaves
// the purl off some of them. It returns how many copies it filled.
func fillPURLs(pkgs []json.RawMessage) (int, error) {
	type key struct{ id, name, version string }
	keyOf := func(raw json.RawMessage) (key, pkgInfo, error) {
		var p pkgInfo
		err := json.Unmarshal(raw, &p)
		return key{p.SPDXID, p.Name, p.VersionInfo}, p, err
	}
	purls := map[key]map[string]bool{}
	for _, raw := range pkgs {
		k, p, err := keyOf(raw)
		if err != nil {
			return 0, err
		}
		if purl := p.purl(); purl != "" {
			if purls[k] == nil {
				purls[k] = map[string]bool{}
			}
			purls[k][purl] = true
		}
	}
	n := 0
	for i, raw := range pkgs {
		k, p, err := keyOf(raw)
		if err != nil {
			return 0, err
		}
		if p.purl() != "" || len(purls[k]) != 1 {
			continue
		}
		var purl string
		for p := range purls[k] {
			purl = p
		}
		var obj object
		if err := json.Unmarshal(raw, &obj); err != nil {
			return 0, err
		}
		refs := append(p.ExternalRefs, externalRef{"PACKAGE-MANAGER", "purl", purl})
		if obj, err = obj.set("externalRefs", refs, ""); err != nil {
			return 0, err
		}
		if pkgs[i], err = json.Marshal(obj); err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

type checksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// reconcileFile matches a file whose SHA256 is in no tar entry against the
// tar by path. linuxkit leaves etc/hostname out of every image and writes its
// own etc/hosts (moby/build/image.go), so the scanner hashed files that do
// not ship as hashed. keep is false for a file absent from the tar; a file
// linuxkit replaced takes the SHA256 of the replacement.
func reconcileFile(raw json.RawMessage, c Content) (out json.RawMessage, keep bool, err error) {
	if c.Paths == nil {
		return raw, true, nil
	}
	var f struct {
		FileName  string     `json:"fileName"`
		Checksums []checksum `json:"checksums"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, false, err
	}
	var sum256 string
	for _, cs := range f.Checksums {
		if cs.Algorithm == "SHA256" {
			sum256 = cs.ChecksumValue
		}
	}
	if _, ok := c.SHA1[sum256]; ok || sum256 == "" {
		return raw, true, nil
	}
	shipped, ok := c.Paths[strings.Trim(path.Clean(f.FileName), "/")]
	switch {
	case !ok:
		return nil, false, nil
	case shipped == "":
		return raw, true, nil
	}
	var obj object
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, false, err
	}
	if obj, err = obj.set("checksums", []checksum{{"SHA256", shipped}}, ""); err != nil {
		return nil, false, err
	}
	out, err = json.Marshal(obj)
	return out, true, err
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
