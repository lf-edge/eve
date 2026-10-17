// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// sbom-stamp rewrites the SPDX document linuxkit merges into a rootfs tar so
// that it names EVE-OS as the described product and is reproducible. linuxkit
// hardcodes the document name ("sbom"), a random documentNamespace, its own
// fixed reproducible-build date and creators, and leaves one DESCRIBES edge
// per input image. sbom-stamp replaces those, adds an EVE-OS package that the
// document describes and that contains the per-image roots, and drops entries
// that linuxkit's merge duplicated byte for byte.
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	rootID        = "SPDXRef-Package-EVE-OS"
	documentID    = "SPDXRef-DOCUMENT"
	lfEdge        = "Organization: LF Edge"
	nsPlaceholder = "https://github.com/lf-edge/eve/spdx/placeholder"
)

// Options carry the product identity stamped into the document.
type Options struct {
	Name          string
	Version       string
	Download      string
	PURL          string
	NamespaceBase string
	Created       time.Time
}

// field is one member of a JSON object, kept in document order.
type field struct {
	Key   string
	Value json.RawMessage
}

type object []field

func (o object) get(key string) (json.RawMessage, bool) {
	for _, f := range o {
		if f.Key == key {
			return f.Value, true
		}
	}
	return nil, false
}

// set replaces key in place, or inserts it after the member named after
// (appending when after is absent).
func (o object) set(key string, v any, after string) (object, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	for i := range o {
		if o[i].Key == key {
			o[i].Value = raw
			return o, nil
		}
	}
	for i := range o {
		if o[i].Key == after {
			o = append(o[:i+1], append(object{{key, raw}}, o[i+1:]...)...)
			return o, nil
		}
	}
	return append(o, field{key, raw}), nil
}

func (o *object) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return errors.New("expected a JSON object")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return err
		}
		*o = append(*o, field{t.(string), v})
	}
	_, err = dec.Token()
	return err
}

func (o object) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(f.Key)
		b.Write(k)
		b.WriteByte(':')
		if err := json.Compact(&b, f.Value); err != nil {
			return nil, err
		}
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// rootPackage is the SPDX package that stands for the EVE-OS image.
type rootPackage struct {
	Name                  string        `json:"name"`
	SPDXID                string        `json:"SPDXID"`
	VersionInfo           string        `json:"versionInfo"`
	Supplier              string        `json:"supplier"`
	DownloadLocation      string        `json:"downloadLocation"`
	FilesAnalyzed         bool          `json:"filesAnalyzed"`
	LicenseConcluded      string        `json:"licenseConcluded"`
	LicenseDeclared       string        `json:"licenseDeclared"`
	CopyrightText         string        `json:"copyrightText"`
	ExternalRefs          []externalRef `json:"externalRefs,omitempty"`
	PrimaryPackagePurpose string        `json:"primaryPackagePurpose"`
}

type externalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type relationship struct {
	SpdxElementID      string `json:"spdxElementId"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

// Stats reports what Stamp changed, and what it could not fix.
type Stats struct {
	DroppedDuplicates int
	Reparented        int
	ConflictingIDs    int
}

// dedup drops byte-identical array entries, keeping the first occurrence.
func dedup(items []json.RawMessage) ([]json.RawMessage, int) {
	seen := map[string]bool{}
	out := items[:0]
	for _, it := range items {
		k := string(it)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, it)
	}
	return out, len(items) - len(out)
}

func array(doc object, key string) ([]json.RawMessage, error) {
	raw, ok := doc.get(key)
	if !ok {
		return nil, nil
	}
	var a []json.RawMessage
	err := json.Unmarshal(raw, &a)
	return a, err
}

func spdxID(item json.RawMessage) string {
	var v struct {
		SPDXID string `json:"SPDXID"`
	}
	_ = json.Unmarshal(item, &v)
	return v.SPDXID
}

// Stamp returns the stamped document. It is idempotent: stamping its own
// output yields the same bytes.
func Stamp(in []byte, o Options) ([]byte, Stats, error) {
	var st Stats
	var doc object
	if err := json.Unmarshal(in, &doc); err != nil {
		return nil, st, err
	}

	pkgs, err := array(doc, "packages")
	if err != nil {
		return nil, st, err
	}
	files, err := array(doc, "files")
	if err != nil {
		return nil, st, err
	}
	rels, err := array(doc, "relationships")
	if err != nil {
		return nil, st, err
	}

	var n int
	pkgs, n = dedup(pkgs)
	st.DroppedDuplicates += n
	files, n = dedup(files)
	st.DroppedDuplicates += n

	ids := map[string]int{}
	hasRoot := false
	for _, list := range [][]json.RawMessage{pkgs, files} {
		for _, it := range list {
			id := spdxID(it)
			ids[id]++
			hasRoot = hasRoot || id == rootID
		}
	}
	for _, c := range ids {
		if c > 1 {
			st.ConflictingIDs++
		}
	}

	if !hasRoot {
		root := rootPackage{
			Name:                  o.Name,
			SPDXID:                rootID,
			VersionInfo:           o.Version,
			Supplier:              lfEdge,
			DownloadLocation:      o.Download,
			LicenseConcluded:      "NOASSERTION",
			LicenseDeclared:       "Apache-2.0",
			CopyrightText:         "NOASSERTION",
			PrimaryPackagePurpose: "OPERATING-SYSTEM",
		}
		if o.PURL != "" {
			root.ExternalRefs = []externalRef{{"PACKAGE-MANAGER", "purl", o.PURL}}
		}
		raw, err := json.Marshal(root)
		if err != nil {
			return nil, st, err
		}
		pkgs = append([]json.RawMessage{raw}, pkgs...)
	}

	// linuxkit keeps each input image's "DOCUMENT DESCRIBES <image root>"
	// edge, so the merged document describes a few dozen anonymous roots
	// and no product. Make EVE-OS the one described package and the parent
	// of those roots.
	for i, it := range rels {
		var r relationship
		if err := json.Unmarshal(it, &r); err != nil {
			return nil, st, err
		}
		if r.SpdxElementID != documentID || r.RelationshipType != "DESCRIBES" ||
			r.RelatedSpdxElement == rootID {
			continue
		}
		var ro object
		if err := json.Unmarshal(it, &ro); err != nil {
			return nil, st, err
		}
		if ro, err = ro.set("spdxElementId", rootID, ""); err != nil {
			return nil, st, err
		}
		if ro, err = ro.set("relationshipType", "CONTAINS", ""); err != nil {
			return nil, st, err
		}
		if rels[i], err = json.Marshal(ro); err != nil {
			return nil, st, err
		}
		st.Reparented++
	}
	rels, n = dedup(rels)
	st.DroppedDuplicates += n
	describes, err := json.Marshal(relationship{documentID, rootID, "DESCRIBES"})
	if err != nil {
		return nil, st, err
	}
	if len(rels) == 0 || !bytes.Equal(rels[0], describes) {
		rels = append([]json.RawMessage{describes}, rels...)
	}

	var ci object
	if raw, ok := doc.get("creationInfo"); ok {
		if err := json.Unmarshal(raw, &ci); err != nil {
			return nil, st, err
		}
	}
	var creators []string
	if raw, ok := ci.get("creators"); ok {
		if err := json.Unmarshal(raw, &creators); err != nil {
			return nil, st, err
		}
	}
	hasLFEdge := false
	for _, c := range creators {
		hasLFEdge = hasLFEdge || c == lfEdge
	}
	if !hasLFEdge {
		creators = append(creators, lfEdge)
	}
	if ci, err = ci.set("creators", creators, ""); err != nil {
		return nil, st, err
	}
	// SPDX 2.3 section 6.9: YYYY-MM-DDThh:mm:ssZ.
	if ci, err = ci.set("created", o.Created.UTC().Format("2006-01-02T15:04:05Z"), "creators"); err != nil {
		return nil, st, err
	}

	for _, s := range []struct {
		key   string
		value any
		after string
	}{
		{"name", o.Name + "-" + o.Version, "SPDXID"},
		{"documentNamespace", nsPlaceholder, "name"},
		{"creationInfo", ci, "documentNamespace"},
		{"documentDescribes", []string{rootID}, "creationInfo"},
		{"packages", pkgs, "documentDescribes"},
		{"files", files, "packages"},
		{"relationships", rels, ""},
	} {
		if doc, err = doc.set(s.key, s.value, s.after); err != nil {
			return nil, st, err
		}
	}

	// The namespace must be unique per document (SPDX 2.3 section 6.5), and
	// reproducible builds need it to be a function of the content. Hash the
	// document with a fixed placeholder namespace, then substitute.
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, st, err
	}
	sum := sha256.Sum256(out)
	ns := fmt.Sprintf("%s/%s-%s-%s", o.NamespaceBase, o.Name, o.Version, hex.EncodeToString(sum[:16]))
	if doc, err = doc.set("documentNamespace", ns, "name"); err != nil {
		return nil, st, err
	}
	out, err = json.Marshal(doc)
	return out, st, err
}

// stampTar rewrites the tar at path with member stamped, streaming through a
// temporary file, and replaces path only if the content changed so that make
// sees an unchanged mtime.
func stampTar(path, member string, o Options) (st Stats, err error) {
	in, err := os.Open(path)
	if err != nil {
		return st, err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return st, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".stamp-*")
	if err != nil {
		return st, err
	}
	defer func() {
		tmp.Close()
		if err != nil {
			os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(fi.Mode().Perm()); err != nil {
		return st, err
	}
	inSum, outSum := sha256.New(), sha256.New()
	src := io.TeeReader(in, inSum)
	tr := tar.NewReader(src)
	tw := tar.NewWriter(io.MultiWriter(tmp, outSum))
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return st, err
		}
		if hdr.Name != member || hdr.Typeflag != tar.TypeReg {
			if err := tw.WriteHeader(hdr); err != nil {
				return st, err
			}
			if _, err := io.Copy(tw, tr); err != nil {
				return st, err
			}
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return st, err
		}
		if body, st, err = Stamp(body, o); err != nil {
			return st, fmt.Errorf("%s: %w", member, err)
		}
		hdr.Size = int64(len(body))
		found = true
		if err := tw.WriteHeader(hdr); err != nil {
			return st, err
		}
		if _, err := tw.Write(body); err != nil {
			return st, err
		}
	}
	if err := tw.Close(); err != nil {
		return st, err
	}
	if !found {
		return st, fmt.Errorf("%s: no member %s", path, member)
	}
	if _, err := io.Copy(io.Discard, src); err != nil {
		return st, err
	}
	if err := tmp.Close(); err != nil {
		return st, err
	}
	if bytes.Equal(inSum.Sum(nil), outSum.Sum(nil)) {
		return st, os.Remove(tmp.Name())
	}
	return st, os.Rename(tmp.Name(), path)
}

// sourceDateEpoch parses SOURCE_DATE_EPOCH (reproducible-builds.org).
func sourceDateEpoch(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("SOURCE_DATE_EPOCH is not set")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("SOURCE_DATE_EPOCH: %w", err)
	}
	return time.Unix(n, 0), nil
}

func main() {
	var o Options
	member := flag.String("member", "sbom.spdx.json", "SPDX document inside the tar")
	flag.StringVar(&o.Name, "name", "", "product name")
	flag.StringVar(&o.Version, "version", "", "product version, e.g. 17.0.1-lts-kvm-amd64")
	flag.StringVar(&o.Download, "download", "NOASSERTION", "SPDX downloadLocation of the product")
	flag.StringVar(&o.PURL, "purl", "", "package URL of the product")
	flag.StringVar(&o.NamespaceBase, "namespace-base", "https://github.com/lf-edge/eve/spdx", "documentNamespace prefix")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s [flags] <rootfs.tar>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 || o.Name == "" || o.Version == "" {
		flag.Usage()
		os.Exit(2)
	}
	var err error
	if o.Created, err = sourceDateEpoch(os.Getenv("SOURCE_DATE_EPOCH")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	st, err := stampTar(flag.Arg(0), *member, o)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "sbom-stamp: %s: %d duplicate entries dropped, %d image roots placed under %s, %d SPDX IDs still not unique\n",
		flag.Arg(0), st.DroppedDuplicates, st.Reparented, rootID, st.ConflictingIDs)
}
