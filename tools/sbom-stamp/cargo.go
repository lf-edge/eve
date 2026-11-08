// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
)

// fromSBOM starts the sourceInfo syft gives a package it read from an SPDX
// document inside an image; the path of that document follows.
const fromSBOM = "acquired package info from SBOM: "

// cargoSources returns the source cargo-sbom recorded for each package in
// doc, keyed by name@version: registry+<index>, git+<url>[?<query>]#<commit>,
// or NONE for a crate in the workspace it was run in. It returns nil for a
// document another tool wrote. A name@version listed with two sources maps to
// "", since syft's package cannot say which one it is.
func cargoSources(doc []byte) map[string]string {
	var d struct {
		CreationInfo struct {
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
		Packages []struct {
			Name             string `json:"name"`
			VersionInfo      string `json:"versionInfo"`
			DownloadLocation string `json:"downloadLocation"`
		} `json:"packages"`
	}
	if json.Unmarshal(doc, &d) != nil {
		return nil
	}
	cargo := false
	for _, c := range d.CreationInfo.Creators {
		cargo = cargo || strings.HasPrefix(c, "Tool: cargo-sbom")
	}
	if !cargo {
		return nil
	}
	m := map[string]string{}
	for _, p := range d.Packages {
		key := p.Name + "@" + p.VersionInfo
		if old, ok := m[key]; ok && old != p.DownloadLocation {
			m[key] = ""
			continue
		}
		m[key] = p.DownloadLocation
	}
	return m
}

// spdxIDString is linuxkit's: it replaces each character an SPDX identifier
// cannot contain with a hyphen. linuxkit scopes the IDs of an image's packages
// with spdxIDString of the directory the image is unpacked in.
func spdxIDString(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '.' || r == '-' || ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') {
			return r
		}
		return '-'
	}, s)
}

// cargoSource returns the source cargo-sbom recorded for p, or "" when p is
// not a package syft read from a cargo-sbom document in the tar. syft keeps
// the purl cargo-sbom writes for crates.io crates but drops the
// downloadLocation, which for git and workspace crates is all there is.
func cargoSource(p pkgInfo, c Content) string {
	path, ok := strings.CutPrefix(p.SourceInfo, fromSBOM)
	if !ok {
		return ""
	}
	scope, _, ok := strings.Cut(strings.TrimPrefix(p.SPDXID, "SPDXRef-"), "-Package-")
	if !ok {
		return ""
	}
	path = "/" + strings.Trim(path, "/")
	found := ""
	for docPath, sources := range c.Cargo {
		dir, ok := strings.CutSuffix(docPath, path)
		if !ok || spdxIDString(strings.Trim(dir, "/")) != scope {
			continue
		}
		src := sources[p.Name+"@"+p.VersionInfo]
		if found != "" && src != found {
			return ""
		}
		found = src
	}
	return found
}

// cargoGit returns the SPDX downloadLocation, git+<url>@<commit>, of a cargo
// git source, git+<url>[?<query>]#<commit>.
func cargoGit(src string) (string, bool) {
	rest, ok := strings.CutPrefix(src, "git+")
	if !ok {
		return "", false
	}
	rest, commit, ok := strings.Cut(rest, "#")
	if !ok || commit == "" {
		return "", false
	}
	repo, _, _ := strings.Cut(rest, "?")
	return "git+" + repo + "@" + commit, true
}

// cargoPURL is the purl of a crate built from a git repository at vcs, a
// downloadLocation from cargoGit.
func cargoPURL(p pkgInfo, vcs string) string {
	return "pkg:cargo/" + purlEscape(p.Name) + "@" + purlEscape(p.VersionInfo) +
		"?vcs_url=" + purlEscape(vcs)
}

// fillCargo gives a crate without a purl that cargo-sbom saw come from git
// the purl and downloadLocation of that repository.
func fillCargo(raw json.RawMessage, c Content) (json.RawMessage, error) {
	var p pkgInfo
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.purl() != "" {
		return raw, nil
	}
	vcs, ok := cargoGit(cargoSource(p, c))
	if !ok {
		return raw, nil
	}
	var po object
	if err := json.Unmarshal(raw, &po); err != nil {
		return nil, err
	}
	po, err := po.set("externalRefs", withPURL(p.ExternalRefs, cargoPURL(p, vcs)), "")
	if err == nil && (p.DownloadLocation == "" || p.DownloadLocation == "NOASSERTION") {
		po, err = po.set("downloadLocation", vcs, "supplier")
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(po)
}
