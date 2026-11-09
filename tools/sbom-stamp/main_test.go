// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// merged mimics linuxkit's merge of two image SBoMs: a random namespace, one
// DESCRIBES edge per image, and the busybox package and file that both images
// ship, under IDs scoped to each image.
func merged(uuid string) []byte {
	return []byte(`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"sbom",` +
		`"documentNamespace":"https://github.com/linuxkit/linuxkit/sbom-` + uuid + `",` +
		`"creationInfo":{"licenseListVersion":"3.20","creators":["Organization: LinuxKit","Tool: linuxkit"],"created":"2017-04-18T16:30:00Z"},` +
		`"packages":[` +
		`{"name":"docker.io/lfedge/eve-a","SPDXID":"SPDXRef-a-DocumentRoot-Directory-sbom","versionInfo":"0123abcd","downloadLocation":"NOASSERTION","packageFileName":"./a"},` +
		`{"name":"busybox","SPDXID":"SPDXRef-a-Package-apk-busybox-1","versionInfo":"1.37.0-r19"},` +
		`{"name":"docker.io/lfedge/eve-b","SPDXID":"SPDXRef-b-DocumentRoot-Directory-sbom","versionInfo":"4567ef01","downloadLocation":"NOASSERTION","packageFileName":"./b"},` +
		`{"name":"busybox","SPDXID":"SPDXRef-b-Package-apk-busybox-1","versionInfo":"1.37.0-r19"}],` +
		`"files":[{"fileName":"a/bin/busybox","SPDXID":"SPDXRef-a-File-bin-busybox-1"},` +
		`{"fileName":"b/bin/busybox","SPDXID":"SPDXRef-b-File-bin-busybox-1"}],` +
		`"relationships":[` +
		`{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-a-DocumentRoot-Directory-sbom","relationshipType":"DESCRIBES"},` +
		`{"spdxElementId":"SPDXRef-a-DocumentRoot-Directory-sbom","relatedSpdxElement":"SPDXRef-a-Package-apk-busybox-1","relationshipType":"CONTAINS"},` +
		`{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-b-DocumentRoot-Directory-sbom","relationshipType":"DESCRIBES"},` +
		`{"spdxElementId":"SPDXRef-a-Package-apk-busybox-1","relatedSpdxElement":"SPDXRef-a-File-bin-busybox-1","relationshipType":"CONTAINS"},` +
		`{"spdxElementId":"SPDXRef-b-Package-apk-busybox-1","relatedSpdxElement":"SPDXRef-b-File-bin-busybox-1","relationshipType":"CONTAINS"}]}`)
}

var opts = Options{
	Name:          "eve",
	Version:       "0.0.0-test-kvm-amd64",
	Download:      "git+https://github.com/lf-edge/eve.git@0123456789abcdef",
	PURL:          "pkg:docker/lfedge/eve@0.0.0-test-kvm-amd64",
	NamespaceBase: "https://github.com/lf-edge/eve/spdx",
	Created:       time.Unix(1760000000, 0),
}

type doc struct {
	Name              string   `json:"name"`
	DocumentNamespace string   `json:"documentNamespace"`
	DocumentDescribes []string `json:"documentDescribes"`
	CreationInfo      struct {
		Creators []string `json:"creators"`
		Created  string   `json:"created"`
	} `json:"creationInfo"`
	Packages      []map[string]any `json:"packages"`
	Files         []map[string]any `json:"files"`
	Relationships []relationship   `json:"relationships"`
}

func stamp(t *testing.T, in []byte) []byte {
	t.Helper()
	out, _, err := Stamp(in, opts, Content{})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestReproducible(t *testing.T) {
	a := stamp(t, merged("adf56734-4194-464a-b5f5-483d845251de"))
	b := stamp(t, merged("cc68af9c-7c96-4808-9d5b-7ec43660805d"))
	if !bytes.Equal(a, b) {
		t.Errorf("builds differing only in linuxkit's random namespace stamp differently")
	}
	changed := bytes.ReplaceAll(merged("adf56734-4194-464a-b5f5-483d845251de"), []byte("1.37.0-r19"), []byte("1.37.0-r20"))
	var x, y doc
	_ = json.Unmarshal(a, &x)
	_ = json.Unmarshal(stamp(t, changed), &y)
	if x.DocumentNamespace == y.DocumentNamespace {
		t.Errorf("different content got the same namespace %s", x.DocumentNamespace)
	}
}

func TestIdempotent(t *testing.T) {
	once := stamp(t, merged("adf56734-4194-464a-b5f5-483d845251de"))
	if twice := stamp(t, once); !bytes.Equal(once, twice) {
		t.Errorf("restamping changed the document:\n%s\n%s", once, twice)
	}
}

func TestDocument(t *testing.T) {
	out, st, err := Stamp(merged("adf56734-4194-464a-b5f5-483d845251de"), opts, Content{})
	if err != nil {
		t.Fatal(err)
	}
	var d doc
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatal(err)
	}
	if d.Name != "eve-0.0.0-test-kvm-amd64" {
		t.Errorf("name %q", d.Name)
	}
	if !strings.HasPrefix(d.DocumentNamespace, "https://github.com/lf-edge/eve/spdx/eve-0.0.0-test-kvm-amd64-") {
		t.Errorf("namespace %q", d.DocumentNamespace)
	}
	if d.CreationInfo.Created != "2025-10-09T08:53:20Z" {
		t.Errorf("created %q", d.CreationInfo.Created)
	}
	if strings.Join(d.CreationInfo.Creators, "|") != "Organization: LinuxKit|Tool: linuxkit|Organization: LF Edge" {
		t.Errorf("creators %q", d.CreationInfo.Creators)
	}
	if len(d.DocumentDescribes) != 1 || d.DocumentDescribes[0] != rootID {
		t.Errorf("documentDescribes %q", d.DocumentDescribes)
	}
	if len(d.Packages) != 5 || d.Packages[0]["SPDXID"] != rootID ||
		d.Packages[0]["supplier"] != "Organization: LF Edge" || d.Packages[0]["licenseDeclared"] != "NOASSERTION" {
		t.Errorf("packages %v", d.Packages)
	}
	if len(d.Files) != 2 {
		t.Errorf("files %v", d.Files)
	}
	var describes, contains []string
	for _, r := range d.Relationships {
		switch {
		case r.RelationshipType == "DESCRIBES":
			describes = append(describes, r.SpdxElementID+">"+r.RelatedSpdxElement)
		case r.SpdxElementID == rootID:
			contains = append(contains, r.RelatedSpdxElement)
		}
	}
	if strings.Join(describes, ",") != documentID+">"+rootID {
		t.Errorf("DESCRIBES %v", describes)
	}
	if strings.Join(contains, ",") != "SPDXRef-a-DocumentRoot-Directory-sbom,SPDXRef-b-DocumentRoot-Directory-sbom" {
		t.Errorf("%s CONTAINS %v", rootID, contains)
	}
	if len(d.Relationships) != 6 {
		t.Errorf("%d relationships, want 6: %v", len(d.Relationships), d.Relationships)
	}
	if st.Reparented != 2 || st.ConflictingIDs != 0 {
		t.Errorf("stats %+v", st)
	}

	// A linuxkit that does not scope IDs to their image repeats them.
	unscoped := bytes.ReplaceAll(merged("adf56734-4194-464a-b5f5-483d845251de"), []byte("SPDXRef-b-Package"), []byte("SPDXRef-a-Package"))
	if _, st, err := Stamp(unscoped, opts, Content{}); err != nil || st.ConflictingIDs != 1 {
		t.Errorf("repeated ID: %d conflicting IDs reported, want 1 (err %v)", st.ConflictingIDs, err)
	}
}

func writeTar(t *testing.T, path string, members map[string][]byte, order []string) {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, n := range order {
		hdr := &tar.Header{Name: n, Mode: 0o644, Size: int64(len(members[n])),
			ModTime: time.Unix(1492533000, 0), Format: tar.FormatPAX,
			PAXRecords: map[string]string{"LINUXKIT.source": "docker.io/lfedge/eve-test"}}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(members[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readTar(t *testing.T, path string) map[string]*tar.Header {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]*tar.Header{}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = hdr
	}
}

func TestStampTar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rootfs.tar")
	members := map[string][]byte{"bin/busybox": []byte("busybox"),
		"sbom.spdx.json": merged("adf56734-4194-464a-b5f5-483d845251de")}
	writeTar(t, path, members, []string{"bin/busybox", "sbom.spdx.json"})
	if _, err := stampTar(path, "sbom.spdx.json", opts); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("stamped tar has mode %v, want the original's 0644", fi.Mode().Perm())
	}
	hdrs := readTar(t, path)
	if len(hdrs) != 2 || hdrs["bin/busybox"].PAXRecords["LINUXKIT.source"] != "docker.io/lfedge/eve-test" {
		t.Errorf("members or their PAX records not preserved: %v", hdrs)
	}
	want := stamp(t, members["sbom.spdx.json"])
	if hdrs["sbom.spdx.json"].Size != int64(len(want)) {
		t.Errorf("sbom member size %d, want %d", hdrs["sbom.spdx.json"].Size, len(want))
	}

	before, _ := os.Stat(path)
	if err := os.Chtimes(path, before.ModTime(), time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := stampTar(path, "sbom.spdx.json", opts); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.Stat(path); !after.ModTime().Equal(time.Unix(1, 0)) {
		t.Errorf("restamping an already stamped tar rewrote it")
	}
	if left, _ := filepath.Glob(path + ".stamp-*"); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}

	if _, err := stampTar(path, "missing.spdx.json", opts); err == nil {
		t.Errorf("a tar without the SBoM member was accepted")
	}
}

// scanned mimics the packages and files of two scanned images: one root with
// the image's directory in the tar, one at the top of the rootfs, and the
// package kinds whose supplier the scanner leaves as NOASSERTION, among them
// a copy of a Go module without its purl in the other image.
func scanned() []byte {
	pkg := func(id, name, version, supplier, description, purl string) string {
		return `{"name":"` + name + `","SPDXID":"` + id + `","versionInfo":"` + version + `","supplier":"` + supplier +
			`","description":"` + description + `","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"` + purl + `"}]}`
	}
	return []byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"sbom","creationInfo":{"creators":["Tool: linuxkit"]},"packages":[` +
		`{"name":"docker.io/lfedge/eve-rngd","SPDXID":"` + rngdRoot + `","versionInfo":"ba4c5b192f086f3d2dfadc46061b71afc44edd62","packageFileName":"./containers/onboot/000-rngd/rootfs"},` +
		`{"name":"docker.io/linuxkit/init","SPDXID":"` + initRoot + `","versionInfo":"075ff447b68e23feef95589c90010a039533e5b5"},` +
		pkg("SPDXRef-r-Package-apk-libtpms-1", "libtpms", "0.10.0", "NOASSERTION", "TPM 2.0 emulation library (built from source)", "pkg:apk/busybox/libtpms@0.10.0") + `,` +
		pkg("SPDXRef-r-Package-apk-busybox-1", "busybox", "1.37.0-r20", "NOASSERTION", "Size optimized toolbox", "pkg:apk/busybox/busybox@1.37.0-r20") + `,` +
		`{"name":"ssl_client","SPDXID":"SPDXRef-r-Package-apk-ssl-client-1","versionInfo":"1.37.0-r20","supplier":"NOASSERTION"},` +
		pkg("SPDXRef-r-Package-apk-musl-1", "musl", "1.2.5-r10", "Person: Natanael Copa (ncopa@alpinelinux.org)", "", "pkg:apk/busybox/musl@1.2.5-r10") + `,` +
		pkg("SPDXRef-r-Package-go-module-pillar-1", "github.com/lf-edge/eve/pkg/pillar", "v0.0.0", "NOASSERTION", "", "pkg:golang/github.com/lf-edge/eve/pkg/pillar@v0.0.0") + `,` +
		pkg("SPDXRef-r-Package-go-module-sys-1", "golang.org/x/sys", "v0.30.0", "NOASSERTION", "", "pkg:golang/golang.org/x/sys@v0.30.0") + `,` +
		`{"name":"golang.org/x/sys","SPDXID":"SPDXRef-i-Package-go-module-sys-1","versionInfo":"v0.30.0","supplier":"NOASSERTION"},` +
		pkg("SPDXRef-r-Package-go-module-unmapped-1", "example.com/unmapped", "v0.9.1", "NOASSERTION", "", "pkg:golang/example.com/unmapped@v0.9.1") + `,` +
		pkg(kernelPackage+"linux-kernel-1", "linux-kernel", "6.18.55-linuxkit-core-92df24b15f57", "NOASSERTION", "", "pkg:generic/linux-kernel@6.18.55-linuxkit-core-92df24b15f57") + `,` +
		`{"name":"golang.org/x/net","SPDXID":"SPDXRef-r-Package-go-module-net-1","versionInfo":"v0.1.0","supplier":"Organization: The Go Authors",` +
		`"licenseConcluded":"NOASSERTION","licenseDeclared":"MIT","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:golang/golang.org/x/net@v0.1.0"}]}],` +
		`"files":[{"fileName":"bin/busybox","SPDXID":"SPDXRef-File-bin-busybox-1","checksums":[{"algorithm":"SHA256","checksumValue":"9d75f0d7c398df565d7ac04c6819b62d6d8f9560f5eb4672596ecd8f7e96ae91"}]},` +
		`{"fileName":"etc/gone","SPDXID":"SPDXRef-File-etc-gone-1","checksums":[{"algorithm":"SHA256","checksumValue":"00"}]},` +
		`{"fileName":"etc/hosts","SPDXID":"SPDXRef-File-etc-hosts-1","checksums":[{"algorithm":"SHA256","checksumValue":"11"}]}],` +
		`"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"` + rngdRoot + `","relationshipType":"DESCRIBES"},` +
		`{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"` + initRoot + `","relationshipType":"DESCRIBES"},` +
		`{"spdxElementId":"SPDXRef-r-Package-apk-busybox-1","relatedSpdxElement":"SPDXRef-File-etc-gone-1","relationshipType":"CONTAINS"},` +
		`{"spdxElementId":"SPDXRef-r-Package-apk-busybox-1","relatedSpdxElement":"SPDXRef-File-etc-hosts-1","relationshipType":"CONTAINS"}]}`)
}

const (
	rngdRoot = "SPDXRef-containers-onboot-000-rngd-rootfs-DocumentRoot-Directory-sbom"
	initRoot = "SPDXRef-docker.io-linuxkit-init-DocumentRoot-Directory-sbom"
)

// content is what stampTar collects from tarWithContent.
var content = Content{
	SHA1: map[string]string{
		"9d75f0d7c398df565d7ac04c6819b62d6d8f9560f5eb4672596ecd8f7e96ae91": "2f106f27fa1f28a8a4e02aeb10d73b78f9c9b24a",
		"4f8a2cc398d8664277a96a7843ab4958ab1d0a347cbe7c071fde0fcb58230793": "abba3508de929934a4e4b5198e00683c2b633bbc",
	},
	Paths: map[string]string{
		"containers/onboot/000-rngd/rootfs":             "",
		"containers/onboot/000-rngd/rootfs/bin/busybox": "9d75f0d7c398df565d7ac04c6819b62d6d8f9560f5eb4672596ecd8f7e96ae91",
		"etc/hosts": "4f8a2cc398d8664277a96a7843ab4958ab1d0a347cbe7c071fde0fcb58230793",
	},
}

func TestFill(t *testing.T) {
	out, st, err := Stamp(scanned(), opts, content)
	if err != nil {
		t.Fatal(err)
	}
	var d doc
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatal(err)
	}
	type want struct{ name, version, supplier, purl string }
	got := map[string]want{}
	for _, p := range d.Packages {
		w := want{name: p["name"].(string)}
		w.version, _ = p["versionInfo"].(string)
		w.supplier, _ = p["supplier"].(string)
		if refs, ok := p["externalRefs"].([]any); ok && len(refs) > 0 {
			w.purl = refs[0].(map[string]any)["referenceLocator"].(string)
		}
		got[p["SPDXID"].(string)] = w
	}
	for id, w := range map[string]want{
		rngdRoot: {"docker.io/lfedge/eve-rngd", "ba4c5b192f086f3d2dfadc46061b71afc44edd62", lfEdge,
			"pkg:docker/lfedge/eve-rngd@ba4c5b192f086f3d2dfadc46061b71afc44edd62"},
		initRoot: {"docker.io/linuxkit/init", "075ff447b68e23feef95589c90010a039533e5b5", linuxKit,
			"pkg:docker/linuxkit/init@075ff447b68e23feef95589c90010a039533e5b5"},
		"SPDXRef-r-Package-apk-libtpms-1":    {"libtpms", "0.10.0", lfEdge, "pkg:generic/libtpms@0.10.0"},
		"SPDXRef-r-Package-apk-busybox-1":    {"busybox", "1.37.0-r20", alpine, "pkg:apk/busybox/busybox@1.37.0-r20"},
		"SPDXRef-r-Package-apk-ssl-client-1": {"ssl_client", "1.37.0-r20", alpine, ""},
		"SPDXRef-r-Package-apk-musl-1": {"musl", "1.2.5-r10", "Person: Natanael Copa (ncopa@alpinelinux.org)",
			"pkg:apk/busybox/musl@1.2.5-r10"},
		"SPDXRef-r-Package-go-module-pillar-1": {"github.com/lf-edge/eve/pkg/pillar", "v0.0.0", lfEdge,
			"pkg:golang/github.com/lf-edge/eve/pkg/pillar@v0.0.0"},
		"SPDXRef-r-Package-go-module-sys-1": {"golang.org/x/sys", "v0.30.0", "Organization: The Go Authors",
			"pkg:golang/golang.org/x/sys@v0.30.0"},
		"SPDXRef-i-Package-go-module-sys-1": {"golang.org/x/sys", "v0.30.0", "Organization: The Go Authors",
			"pkg:golang/golang.org/x/sys@v0.30.0"},
		"SPDXRef-r-Package-go-module-unmapped-1": {"example.com/unmapped", "v0.9.1", "NOASSERTION",
			"pkg:golang/example.com/unmapped@v0.9.1"},
	} {
		if got[id] != w {
			t.Errorf("%s: got %+v, want %+v", id, got[id], w)
		}
	}
	for id, want := range map[string]any{
		rngdRoot:                                 nil,
		initRoot:                                 nil,
		"SPDXRef-r-Package-apk-busybox-1":        nil,
		"SPDXRef-r-Package-go-module-pillar-1":   "Apache-2.0",
		"SPDXRef-r-Package-go-module-sys-1":      "BSD-3-Clause",
		"SPDXRef-i-Package-go-module-sys-1":      "BSD-3-Clause",
		"SPDXRef-r-Package-go-module-unmapped-1": nil,
		"SPDXRef-r-Package-go-module-net-1":      "MIT",
		kernelPackage + "linux-kernel-1":         kernelLicense,
	} {
		for _, p := range d.Packages {
			if p["SPDXID"] == id && p["licenseDeclared"] != want {
				t.Errorf("%s: licenseDeclared %v, want %v", id, p["licenseDeclared"], want)
			}
		}
	}
	sums := d.Files[0]["checksums"].([]any)
	if len(sums) != 2 || sums[1].(map[string]any)["checksumValue"] != "2f106f27fa1f28a8a4e02aeb10d73b78f9c9b24a" {
		t.Errorf("bin/busybox checksums %v", sums)
	}
	// etc/gone is not in the tar, and etc/hosts holds other content there.
	if len(d.Files) != 2 || d.Files[1]["fileName"] != "etc/hosts" {
		t.Fatalf("files %v, want bin/busybox and etc/hosts", d.Files)
	}
	wantSums := `[{"algorithm":"SHA256","checksumValue":"4f8a2cc398d8664277a96a7843ab4958ab1d0a347cbe7c071fde0fcb58230793"},` +
		`{"algorithm":"SHA1","checksumValue":"abba3508de929934a4e4b5198e00683c2b633bbc"}]`
	if got, _ := json.Marshal(d.Files[1]["checksums"]); string(got) != wantSums {
		t.Errorf("etc/hosts checksums %s, want %s", got, wantSums)
	}
	for _, r := range d.Relationships {
		if r.RelatedSpdxElement == "SPDXRef-File-etc-gone-1" {
			t.Errorf("relationship to the dropped etc/gone kept: %+v", r)
		}
	}
	if st.NoSupplier != 1 || st.NoLicense != 5 || st.NoSHA1 != 0 || st.AbsentFiles != 1 || st.ReplacedFiles != 1 {
		t.Errorf("stats %+v, want 1 package without supplier, 5 without license, 1 file dropped, 1 rehashed, "+
			"none without SHA1", st)
	}
	if again, _, _ := Stamp(out, opts, content); !bytes.Equal(out, again) {
		t.Errorf("restamping a filled document changed it")
	}
}

// tarWithContent writes the image directory and file content behind
// content, followed by the members given.
func tarWithContent(t *testing.T, path string, members ...[2]string) {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	write := func(hdr *tar.Header, body string) {
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	write(&tar.Header{Name: "containers/onboot/000-rngd/rootfs/", Typeflag: tar.TypeDir, Mode: 0o755}, "")
	write(&tar.Header{Name: "containers/onboot/000-rngd/rootfs/bin/busybox", Typeflag: tar.TypeReg, Mode: 0o755, Size: 7}, "busybox")
	write(&tar.Header{Name: "etc/hosts", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5}, "hosts")
	for _, m := range members {
		write(&tar.Header{Name: m[0], Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(m[1]))}, m[1])
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestStampTarContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rootfs.tar")
	tarWithContent(t, path, [2]string{"sbom.spdx.json", string(scanned())})
	if _, err := stampTar(path, "sbom.spdx.json", opts); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	tr := tar.NewReader(f)
	var got []byte
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == "sbom.spdx.json" {
			if got, err = io.ReadAll(tr); err != nil {
				t.Fatal(err)
			}
		}
	}
	if want, _, _ := Stamp(scanned(), opts, content); !bytes.Equal(got, want) {
		t.Errorf("stampTar did not collect the tar's content:\n%s\n%s", got, want)
	}

	tarWithContent(t, path, [2]string{"sbom.spdx.json", string(scanned())}, [2]string{"etc/late", "late"})
	if _, err := stampTar(path, "sbom.spdx.json", opts); err == nil {
		t.Errorf("a tar with entries after the SBoM was accepted")
	}
}

func TestImageRef(t *testing.T) {
	for ref, w := range map[string][3]string{
		"docker.io/lfedge/eve-rngd:ba4c5b19": {"docker.io", "lfedge/eve-rngd", "ba4c5b19"},
		"linuxkit/sysctl:43ac1d39":           {"docker.io", "linuxkit/sysctl", "43ac1d39"},
		"ghcr.io/o/i:t@sha256:00ff":          {"ghcr.io", "o/i", "sha256:00ff"},
		"localhost:5000/o/i:t":               {"localhost:5000", "o/i", "t"},
	} {
		r, repo, v, ok := imageRef(ref)
		if !ok || [3]string{r, repo, v} != w {
			t.Errorf("%s: got %s %s %s %v", ref, r, repo, v, ok)
		}
	}
	for _, ref := range []string{"linuxkit.volumes", "LINUXKIT.apkinit", "docker.io/lfedge/eve-rngd"} {
		if _, _, _, ok := imageRef(ref); ok {
			t.Errorf("%s parsed as an image", ref)
		}
	}
	if p := dockerPURL("ghcr.io", "o/i", "sha256:00ff"); p != "pkg:docker/o/i@sha256%3A00ff?repository_url=ghcr.io" {
		t.Errorf("purl %s", p)
	}
}

func TestFillPURLs(t *testing.T) {
	cpe := `{"referenceCategory":"SECURITY","referenceType":"cpe23Type","referenceLocator":"cpe:2.3:a:zlib:zlib:1.3.2-r0:*:*:*:*:*:*:*"}`
	purl := func(p string) string {
		return `,{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"` + p + `"}`
	}
	pkg := func(id, version, refs string) json.RawMessage {
		return json.RawMessage(`{"name":"zlib","SPDXID":"` + id + `","versionInfo":"` + version +
			`","externalRefs":[` + cpe + refs + `]}`)
	}
	zlib := "pkg:apk/busybox/zlib@1.3.2-r0?arch=x86_64"
	zlib2 := "pkg:apk/alpine/zlib@1.3.2-r0?arch=x86_64"
	zlib3 := "pkg:apk/busybox/zlib@1.3.3-r0?arch=x86_64"
	pkgs := []json.RawMessage{
		pkg("SPDXRef-a-Package-apk-zlib-1", "1.3.2-r0", ""),
		pkg("SPDXRef-b-Package-apk-zlib-1", "1.3.2-r0", purl(zlib)),
		pkg("SPDXRef-c-Package-apk-zlib-1", "1.3.1-r2", ""), // another version: not a copy
		pkg("SPDXRef-a-Package-apk-zlib-2", "1.3.2-r0", ""), // another scanner ID: not a copy of -1
		pkg("SPDXRef-b-Package-apk-zlib-2", "1.3.2-r0", purl(zlib2)),
		pkg("SPDXRef-a-Package-apk-zlib-3", "1.3.3-r0", ""), // copies disagree: left alone
		pkg("SPDXRef-b-Package-apk-zlib-3", "1.3.3-r0", purl(zlib3)),
		pkg("SPDXRef-c-Package-apk-zlib-3", "1.3.3-r0", purl(zlib3+"&x=1")),
	}
	n, err := fillPURLs(pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("filled %d, want 2", n)
	}
	for i, purl := range map[int]string{0: purl(zlib), 3: purl(zlib2)} {
		if want := pkg(fmt.Sprintf("SPDXRef-a-Package-apk-zlib-%d", i/3+1), "1.3.2-r0", purl); !bytes.Equal(pkgs[i], want) {
			t.Errorf("package %d:\n%s\nwant\n%s", i, pkgs[i], want)
		}
	}
	for _, i := range []int{2, 5} {
		if (pkgInfo{ExternalRefs: refsOf(t, pkgs[i])}).purl() != "" {
			t.Errorf("package %d got a purl: %s", i, pkgs[i])
		}
	}
}

func refsOf(t *testing.T, raw json.RawMessage) []externalRef {
	t.Helper()
	var p pkgInfo
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p.ExternalRefs
}

func TestSourcePURL(t *testing.T) {
	cpe := externalRef{"SECURITY", "cpe23Type", "cpe:2.3:a:qemu:qemu:11.1.2:*:*:*:*:*:*:*"}
	apk := externalRef{"PACKAGE-MANAGER", "purl", "pkg:apk/busybox/qemu@11.1.2?arch=x86_64&distro=busybox-1.37.0"}
	for _, tc := range []struct {
		p    pkgInfo
		want string
		refs []externalRef
	}{
		{pkgInfo{Name: "qemu", VersionInfo: "11.1.2", ExternalRefs: []externalRef{cpe, apk}},
			"pkg:generic/qemu@11.1.2", []externalRef{cpe, {"PACKAGE-MANAGER", "purl", "pkg:generic/qemu@11.1.2"}}},
		{pkgInfo{Name: "linux-firmware", VersionInfo: "20260916"},
			"pkg:generic/linux-firmware@20260916", []externalRef{{"PACKAGE-MANAGER", "purl", "pkg:generic/linux-firmware@20260916"}}},
		{pkgInfo{Name: "x y", VersionInfo: "1.0+git/1@2"}, "pkg:generic/x%20y@1.0%2Bgit%2F1%402", nil},
	} {
		got := sourcePURL(tc.p)
		if got != tc.want {
			t.Errorf("sourcePURL(%+v) = %q, want %q", tc.p, got, tc.want)
		}
		if refs := withPURL(tc.p.ExternalRefs, got); tc.refs != nil && !reflect.DeepEqual(refs, tc.refs) {
			t.Errorf("withPURL = %+v, want %+v", refs, tc.refs)
		}
	}
}

func TestSuppliers(t *testing.T) {
	m, err := parseSuppliers("# comment\n\npkg:golang/github.com/sirupsen\tPerson: Simon Eskildsen\n" +
		"pkg:golang/k8s.io\tOrganization: Kubernetes\npkg:golang/k8s.io/klog\tOrganization: klog\n" +
		"pkg:cargo/serde\tOrganization: serde-rs\n")
	if err != nil {
		t.Fatal(err)
	}
	for purl, want := range map[string]string{
		"pkg:golang/github.com/sirupsen/logrus@v1.9.3":  "Person: Simon Eskildsen",
		"pkg:golang/k8s.io/api@v0.31.0":                 "Organization: Kubernetes",
		"pkg:golang/k8s.io/klog/v2@v2.130.1":            "Organization: klog",
		"pkg:cargo/serde@1.0.219":                       "Organization: serde-rs",
		"pkg:cargo/serde_json@1.0.140":                  "",
		"pkg:golang/github.com/sirupsenx/logrus@v1.0.0": "",
		"pkg:golang/k8s.io#sub":                         "Organization: Kubernetes",
	} {
		if got := mappedSupplier(m, purl); got != want {
			t.Errorf("mappedSupplier(%q) = %q, want %q", purl, got, want)
		}
	}
	for _, bad := range []string{
		"pkg:cargo/serde Organization: serde-rs\n",
		"pkg:cargo/serde@1.0\tOrganization: serde-rs\n",
		"pkg:cargo/serde\tserde-rs\n",
		"pkg:cargo/serde\tPerson: a\npkg:cargo/serde\tPerson: b\n",
	} {
		if _, err := parseSuppliers(bad); err == nil {
			t.Errorf("parseSuppliers(%q) succeeded", bad)
		}
	}
	if len(suppliers) == 0 {
		t.Error("suppliers.txt has no entries")
	}
}

func TestLicenses(t *testing.T) {
	m, err := parseLicenses("# comment\n\npkg:golang/go.opentelemetry.io/otel\tApache-2.0 AND BSD-3-Clause\n" +
		"pkg:golang/go.opentelemetry.io/otel@v1.31.0\tApache-2.0\n" +
		"pkg:golang/github.com/lf-edge/eve\tApache-2.0\n" +
		"pkg:golang/github.com/google/fscrypt@v0.3.4%2Bdirty\t(MIT OR Apache-2.0)\n" +
		"pkg:generic/linux\tGPL-2.0-only WITH Linux-syscall-note\n")
	if err != nil {
		t.Fatal(err)
	}
	for purl, want := range map[string]string{
		"pkg:golang/go.opentelemetry.io/otel@v1.31.0":                 "Apache-2.0",
		"pkg:golang/go.opentelemetry.io/otel@v1.45.0":                 "Apache-2.0 AND BSD-3-Clause",
		"pkg:golang/go.opentelemetry.io/otel/trace@v1.31.0":           "Apache-2.0 AND BSD-3-Clause",
		"pkg:golang/github.com/lf-edge/eve/pkg/pillar@v0.0.0":         "Apache-2.0",
		"pkg:golang/github.com/lf-edge/eve-api/go@v0.0.0":             "",
		"pkg:golang/github.com/google/fscrypt@v0.3.4%2Bdirty":         "(MIT OR Apache-2.0)",
		"pkg:golang/github.com/google/fscrypt@v0.3.5":                 "",
		"pkg:generic/linux@6.18?arch=amd64#sub":                       "GPL-2.0-only WITH Linux-syscall-note",
		"pkg:golang/go.opentelemetry.io/otel@v1.31.0?type=module#sub": "Apache-2.0",
	} {
		if got := mappedLicense(m, purl); got != want {
			t.Errorf("mappedLicense(%q) = %q, want %q", purl, got, want)
		}
	}
	for _, bad := range []string{
		"pkg:cargo/serde MIT\n",
		"pkg:cargo/serde@\tMIT\n",
		"pkg:cargo/serde?a=b\tMIT\n",
		"pkg:cargo/serde\tNOASSERTION\n",
		"pkg:cargo/serde\tMIT AND AND BSD-3-Clause\n",
		"pkg:cargo/serde\tMIT and BSD-3-Clause\n",
		"pkg:cargo/serde\tMIT\npkg:cargo/serde\tBSD-3-Clause\n",
	} {
		if _, err := parseLicenses(bad); err == nil {
			t.Errorf("parseLicenses(%q) succeeded", bad)
		}
	}
	if _, err := parseSuppliers("pkg:cargo/serde@1.0\tPerson: a\n"); err == nil {
		t.Error("parseSuppliers accepted a versioned prefix")
	}
	if len(licenses) == 0 {
		t.Error("licenses.txt has no entries")
	}
}
