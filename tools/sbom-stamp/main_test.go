// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// merged mimics linuxkit's merge of two image SBoMs: a random namespace, one
// DESCRIBES edge per image, and the shared busybox package, its file and its
// edges repeated once per image.
func merged(uuid string) []byte {
	return []byte(`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"sbom",` +
		`"documentNamespace":"https://github.com/linuxkit/linuxkit/sbom-` + uuid + `",` +
		`"creationInfo":{"licenseListVersion":"3.20","creators":["Organization: LinuxKit","Tool: linuxkit"],"created":"2017-04-18T16:30:00Z"},` +
		`"packages":[` +
		`{"name":"sbom","SPDXID":"SPDXRef-DocumentRoot-Directory-a","downloadLocation":"NOASSERTION"},` +
		`{"name":"busybox","SPDXID":"SPDXRef-Package-apk-busybox-1","versionInfo":"1.37.0-r19"},` +
		`{"name":"sbom","SPDXID":"SPDXRef-DocumentRoot-Directory-b","downloadLocation":"NOASSERTION"},` +
		`{"name":"busybox","SPDXID":"SPDXRef-Package-apk-busybox-1","versionInfo":"1.37.0-r19"}],` +
		`"files":[{"fileName":"bin/busybox","SPDXID":"SPDXRef-File-bin-busybox-1"},` +
		`{"fileName":"bin/busybox","SPDXID":"SPDXRef-File-bin-busybox-1"}],` +
		`"relationships":[` +
		`{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-DocumentRoot-Directory-a","relationshipType":"DESCRIBES"},` +
		`{"spdxElementId":"SPDXRef-DocumentRoot-Directory-a","relatedSpdxElement":"SPDXRef-Package-apk-busybox-1","relationshipType":"CONTAINS"},` +
		`{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-DocumentRoot-Directory-b","relationshipType":"DESCRIBES"},` +
		`{"spdxElementId":"SPDXRef-Package-apk-busybox-1","relatedSpdxElement":"SPDXRef-File-bin-busybox-1","relationshipType":"CONTAINS"},` +
		`{"spdxElementId":"SPDXRef-Package-apk-busybox-1","relatedSpdxElement":"SPDXRef-File-bin-busybox-1","relationshipType":"CONTAINS"}]}`)
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
	changed := bytes.Replace(merged("adf56734-4194-464a-b5f5-483d845251de"), []byte("1.37.0-r19"), []byte("1.37.0-r20"), -1)
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
	if len(d.Packages) != 4 || d.Packages[0]["SPDXID"] != rootID ||
		d.Packages[0]["supplier"] != "Organization: LF Edge" {
		t.Errorf("packages %v", d.Packages)
	}
	if len(d.Files) != 1 {
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
	if strings.Join(contains, ",") != "SPDXRef-DocumentRoot-Directory-a,SPDXRef-DocumentRoot-Directory-b" {
		t.Errorf("%s CONTAINS %v", rootID, contains)
	}
	if len(d.Relationships) != 5 {
		t.Errorf("%d relationships, want 5: %v", len(d.Relationships), d.Relationships)
	}
	if st.DroppedDuplicates != 3 || st.Reparented != 2 || st.ConflictingIDs != 0 {
		t.Errorf("stats %+v", st)
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
	defer f.Close()
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
// package kinds whose supplier the scanner leaves as NOASSERTION.
func scanned() []byte {
	pkg := func(id, name, version, supplier, description, purl string) string {
		return `{"name":"` + name + `","SPDXID":"` + id + `","versionInfo":"` + version + `","supplier":"` + supplier +
			`","description":"` + description + `","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"` + purl + `"}]}`
	}
	return []byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"sbom","creationInfo":{"creators":["Tool: linuxkit"]},"packages":[` +
		`{"name":"sbom","SPDXID":"SPDXRef-DocumentRoot-Directory-sbom","packageFileName":"containers/onboot/000-rngd/rootfs"},` +
		`{"name":"core","SPDXID":"SPDXRef-DocumentRoot-Directory-core"},` +
		pkg("SPDXRef-Package-apk-libtpms-1", "libtpms", "0.10.0", "NOASSERTION", "TPM 2.0 emulation library (built from source)", "pkg:apk/busybox/libtpms@0.10.0") + `,` +
		pkg("SPDXRef-Package-apk-busybox-1", "busybox", "1.37.0-r20", "NOASSERTION", "Size optimized toolbox", "pkg:apk/busybox/busybox@1.37.0-r20") + `,` +
		`{"name":"ssl_client","SPDXID":"SPDXRef-Package-apk-ssl-client-1","versionInfo":"1.37.0-r20","supplier":"NOASSERTION"},` +
		pkg("SPDXRef-Package-apk-musl-1", "musl", "1.2.5-r10", "Person: Natanael Copa (ncopa@alpinelinux.org)", "", "pkg:apk/busybox/musl@1.2.5-r10") + `,` +
		pkg("SPDXRef-Package-go-module-pillar-1", "github.com/lf-edge/eve/pkg/pillar", "v0.0.0", "NOASSERTION", "", "pkg:golang/github.com/lf-edge/eve/pkg/pillar@v0.0.0") + `,` +
		pkg("SPDXRef-Package-go-module-errors-1", "github.com/pkg/errors", "v0.9.1", "NOASSERTION", "", "pkg:golang/github.com/pkg/errors@v0.9.1") + `],` +
		`"files":[{"fileName":"bin/busybox","SPDXID":"SPDXRef-File-bin-busybox-1","checksums":[{"algorithm":"SHA256","checksumValue":"9d75f0d7c398df565d7ac04c6819b62d6d8f9560f5eb4672596ecd8f7e96ae91"}]},` +
		`{"fileName":"etc/gone","SPDXID":"SPDXRef-File-etc-gone-1","checksums":[{"algorithm":"SHA256","checksumValue":"00"}]}],` +
		`"relationships":[]}`)
}

// content is what stampTar collects from tarWithContent.
var content = Content{
	SHA1:   map[string]string{"9d75f0d7c398df565d7ac04c6819b62d6d8f9560f5eb4672596ecd8f7e96ae91": "2f106f27fa1f28a8a4e02aeb10d73b78f9c9b24a"},
	Images: map[string]string{"containers/onboot/000-rngd/rootfs": "docker.io/lfedge/eve-rngd:ba4c5b192f086f3d2dfadc46061b71afc44edd62"},
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
		"SPDXRef-DocumentRoot-Directory-sbom": {"lfedge/eve-rngd", "ba4c5b192f086f3d2dfadc46061b71afc44edd62", lfEdge,
			"pkg:docker/lfedge/eve-rngd@ba4c5b192f086f3d2dfadc46061b71afc44edd62"},
		"SPDXRef-DocumentRoot-Directory-core": {"core", opts.Version, lfEdge, ""},
		"SPDXRef-Package-apk-libtpms-1":       {"libtpms", "0.10.0", lfEdge, "pkg:apk/busybox/libtpms@0.10.0"},
		"SPDXRef-Package-apk-busybox-1":       {"busybox", "1.37.0-r20", alpine, "pkg:apk/busybox/busybox@1.37.0-r20"},
		"SPDXRef-Package-apk-ssl-client-1":    {"ssl_client", "1.37.0-r20", alpine, ""},
		"SPDXRef-Package-apk-musl-1": {"musl", "1.2.5-r10", "Person: Natanael Copa (ncopa@alpinelinux.org)",
			"pkg:apk/busybox/musl@1.2.5-r10"},
		"SPDXRef-Package-go-module-pillar-1": {"github.com/lf-edge/eve/pkg/pillar", "v0.0.0", lfEdge,
			"pkg:golang/github.com/lf-edge/eve/pkg/pillar@v0.0.0"},
		"SPDXRef-Package-go-module-errors-1": {"github.com/pkg/errors", "v0.9.1", "NOASSERTION",
			"pkg:golang/github.com/pkg/errors@v0.9.1"},
	} {
		if got[id] != w {
			t.Errorf("%s: got %+v, want %+v", id, got[id], w)
		}
	}
	sums := d.Files[0]["checksums"].([]any)
	if len(sums) != 2 || sums[1].(map[string]any)["checksumValue"] != "2f106f27fa1f28a8a4e02aeb10d73b78f9c9b24a" {
		t.Errorf("bin/busybox checksums %v", sums)
	}
	if st.NoSupplier != 1 || st.NoSHA1 != 1 {
		t.Errorf("stats %+v, want 1 package without supplier and 1 file without SHA1", st)
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
	write(&tar.Header{Name: "containers/onboot/000-rngd/rootfs/", Typeflag: tar.TypeDir, Mode: 0o755, Format: tar.FormatPAX,
		PAXRecords: map[string]string{"LINUXKIT.source": content.Images["containers/onboot/000-rngd/rootfs"]}}, "")
	write(&tar.Header{Name: "containers/onboot/000-rngd/rootfs/bin/busybox", Typeflag: tar.TypeReg, Mode: 0o755, Size: 7}, "busybox")
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
	defer f.Close()
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
