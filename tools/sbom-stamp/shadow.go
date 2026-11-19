// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"path"
	"strings"
)

type fileEntry struct {
	id, name, sum string
}

// dropShadowed removes the files and packages of an image that a later image
// overwrote. linuxkit appends each init image to the rootfs tar, so a path two
// images write appears twice and only the last copy ships, while the scanner
// still lists the earlier image's file and package. A file entry is shadowed
// when the tar ships other content at its path and another entry describes
// that content. A package other than an image root goes when none of its files
// ships, or when the content replacing one of them belongs to a package of the
// same name, which is then the version installed there, unless it ships a file
// no remaining package lists. A package that loses only files another package
// replaced stays: it still ships the rest. A dropped package's files go with it
// when a remaining package lists the same content at the same path.
func dropShadowed(pkgs, files, rels []json.RawMessage, roots map[string]bool, c Content) (
	[]json.RawMessage, []json.RawMessage, []json.RawMessage, int, int, error) {
	if c.Paths == nil {
		return pkgs, files, rels, 0, 0, nil
	}
	entries := make([]fileEntry, len(files))
	byPath := map[string][]fileEntry{}
	for i, raw := range files {
		var f struct {
			SPDXID    string     `json:"SPDXID"`
			FileName  string     `json:"fileName"`
			Checksums []checksum `json:"checksums"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, nil, nil, 0, 0, err
		}
		e := fileEntry{id: f.SPDXID, name: strings.Trim(path.Clean(f.FileName), "/")}
		for _, cs := range f.Checksums {
			if cs.Algorithm == "SHA256" {
				e.sum = cs.ChecksumValue
			}
		}
		entries[i] = e
		byPath[e.name] = append(byPath[e.name], e)
	}
	// winners maps each shadowed file to the entries describing what ships.
	winners := map[string][]fileEntry{}
	for _, e := range entries {
		shipped := c.Paths[e.name]
		if shipped == "" || e.sum == "" || e.sum == shipped {
			continue
		}
		for _, o := range byPath[e.name] {
			if o.sum == shipped {
				winners[e.id] = append(winners[e.id], o)
			}
		}
	}
	if len(winners) == 0 {
		return pkgs, files, rels, 0, 0, nil
	}

	names := map[string]string{}
	for _, raw := range pkgs {
		var p struct {
			SPDXID string `json:"SPDXID"`
			Name   string `json:"name"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, nil, nil, 0, 0, err
		}
		names[p.SPDXID] = p.Name
	}
	isFile := map[string]bool{}
	for _, e := range entries {
		isFile[e.id] = true
	}
	owners := map[string][]string{}
	contents := map[string][]string{}
	for _, raw := range rels {
		var r relationship
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, nil, nil, 0, 0, err
		}
		if r.RelationshipType == "CONTAINS" && isFile[r.RelatedSpdxElement] {
			if _, ok := names[r.SpdxElementID]; ok {
				owners[r.RelatedSpdxElement] = append(owners[r.RelatedSpdxElement], r.SpdxElementID)
				contents[r.SpdxElementID] = append(contents[r.SpdxElementID], r.RelatedSpdxElement)
			}
		}
	}

	dropped := map[string]bool{}
	for id := range winners {
		dropped[id] = true
	}
	candidates := map[string]bool{}
	for pkg, fl := range contents {
		if roots[pkg] || pkg == rootID {
			continue
		}
		all, replaced := true, false
		for _, f := range fl {
			ws, ok := winners[f]
			all = all && ok
			for _, w := range ws {
				for _, o := range owners[w.id] {
					replaced = replaced || (o != pkg && names[o] == names[pkg])
				}
			}
		}
		if all || replaced {
			candidates[pkg] = true
		}
	}
	// listed reports whether a package outside gone lists e's content at e's path.
	listed := func(e fileEntry, gone map[string]bool) bool {
		for _, o := range byPath[e.name] {
			if o.sum != e.sum {
				continue
			}
			for _, p := range owners[o.id] {
				if !gone[p] {
					return true
				}
			}
		}
		return false
	}
	byID := map[string]fileEntry{}
	for _, e := range entries {
		byID[e.id] = e
	}
	nPkgs := 0
	for pkg := range candidates {
		unique := false
		for _, f := range contents[pkg] {
			e := byID[f]
			unique = unique || (e.sum != "" && e.sum == c.Paths[e.name] && !listed(e, candidates))
		}
		if !unique {
			dropped[pkg] = true
			nPkgs++
		}
	}
	for pkg := range candidates {
		if !dropped[pkg] {
			continue
		}
		for _, f := range contents[pkg] {
			orphan := true
			for _, o := range owners[f] {
				orphan = orphan && dropped[o]
			}
			if orphan && listed(byID[f], dropped) {
				dropped[f] = true
			}
		}
	}

	keep := func(list []json.RawMessage) []json.RawMessage {
		kept := list[:0]
		for _, raw := range list {
			if !dropped[spdxID(raw)] {
				kept = append(kept, raw)
			}
		}
		return kept
	}
	pkgs, files = keep(pkgs), keep(files)
	keptRels := rels[:0]
	for _, raw := range rels {
		var r relationship
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, nil, nil, 0, 0, err
		}
		if !dropped[r.SpdxElementID] && !dropped[r.RelatedSpdxElement] {
			keptRels = append(keptRels, raw)
		}
	}
	nFiles := 0
	for _, e := range entries {
		if dropped[e.id] {
			nFiles++
		}
	}
	return pkgs, files, keptRels, nFiles, nPkgs, nil
}
