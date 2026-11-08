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
	"testing"
)

const (
	crosstermGit = "git+https://github.com/crossterm-rs/crossterm.git?rev=69249c8#69249c88fed67ee917218dc7ccb8a866f391beed"
	crosstermVCS = "git+https://github.com/crossterm-rs/crossterm.git@69249c88fed67ee917218dc7ccb8a866f391beed"
	fromRootSBOM = fromSBOM + "/sbom.spdx.json"
)

// cargoDoc is an SPDX document as cargo-sbom writes it, or as another tool
// does when creator is not cargo-sbom.
func cargoDoc(creator string) string {
	return `{"creationInfo":{"creators":["` + creator + `"]},"packages":[` +
		`{"name":"crossterm","versionInfo":"0.28.1","downloadLocation":"` + crosstermGit + `"},` +
		`{"name":"vector-common-macros","versionInfo":"0.1.0","downloadLocation":"NONE"},` +
		`{"name":"tokio","versionInfo":"1.49.0","downloadLocation":"registry+https://github.com/rust-lang/crates.io-index",` +
		`"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:cargo/tokio@1.49.0"}]}]}`
}

// withCargo mimics the merged document of a rootfs with vector, whose
// cargo-sbom document syft read, the eve-kernel image, and node-exporter.
// Image x carries a crossterm from a document cargo-sbom did not write.
func withCargo() []byte {
	p := func(id, name, version, sourceInfo, purl string) string {
		s := `{"name":"` + name + `","SPDXID":"` + id + `","versionInfo":"` + version +
			`","supplier":"NOASSERTION","downloadLocation":"NOASSERTION","sourceInfo":"` + sourceInfo + `"`
		if purl != "" {
			s += `,"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"` + purl + `"}]`
		}
		return s + `}`
	}
	return []byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"sbom",` +
		`"creationInfo":{"creators":["Tool: linuxkit"],"created":"2017-04-18T16:30:00Z"},"packages":[` +
		p("SPDXRef-containers-services-vector-lower-Package-crossterm-0.28.1", "crossterm", "0.28.1", fromRootSBOM, "") + `,` +
		p("SPDXRef-containers-services-vector-lower-Package-vector-common-macros-0.1.0", "vector-common-macros", "0.1.0", fromRootSBOM, "") + `,` +
		p("SPDXRef-containers-services-x-lower-Package-crossterm-0.28.1", "crossterm", "0.28.1", fromRootSBOM, "") + `,` +
		p("SPDXRef-docker.io-lfedge-eve-kernel-Package-linux-kernel-linux-kernel-1", "linux-kernel",
			"6.18.55-linuxkit-core-92df24b15f57", "", "pkg:generic/linux-kernel@6.18.55-linuxkit-core-92df24b15f57") + `,` +
		p("SPDXRef-docker.io-example-kernel-Package-linux-kernel-linux-kernel-1", "linux-kernel",
			"6.18.55-linuxkit-core-92df24b15f57", "", "pkg:generic/linux-kernel@6.18.55-linuxkit-core-92df24b15f57") + `,` +
		p("SPDXRef-containers-services-node-exporter-lower-Package-binary-busybox-1", "busybox", "1.36.1", "", "pkg:generic/busybox@1.36.1") +
		`],"relationships":[]}`)
}

func TestCargoSources(t *testing.T) {
	if got := cargoSources([]byte(cargoDoc("Tool: syft-1.51.0"))); got != nil {
		t.Errorf("a document cargo-sbom did not write gave %v", got)
	}
	if got := cargoSources([]byte("not json")); got != nil {
		t.Errorf("an invalid document gave %v", got)
	}
	got := cargoSources([]byte(cargoDoc("Tool: cargo-sbom-v0.9.1")))
	if got["crossterm@0.28.1"] != crosstermGit || got["vector-common-macros@0.1.0"] != "NONE" {
		t.Errorf("sources %v", got)
	}
	twice := `{"creationInfo":{"creators":["Tool: cargo-sbom-v0.9.1"]},"packages":[` +
		`{"name":"a","versionInfo":"1","downloadLocation":"NONE"},` +
		`{"name":"a","versionInfo":"1","downloadLocation":"` + crosstermGit + `"}]}`
	if got := cargoSources([]byte(twice)); got["a@1"] != "" {
		t.Errorf("a crate with two sources resolved to %q", got["a@1"])
	}
}

func TestCargoGit(t *testing.T) {
	for src, want := range map[string]string{
		crosstermGit: crosstermVCS,
		"git+https://github.com/tokio-rs/tracing?rev=e0642d9#e0642d949891546a3bb7e47080365ee7274f05cd": "git+https://github.com/tokio-rs/tracing@e0642d949891546a3bb7e47080365ee7274f05cd",
		"git+https://github.com/a/b.git": "",
		"NONE":                           "",
		"registry+https://github.com/rust-lang/crates.io-index": "",
	} {
		if got, ok := cargoGit(src); got != want || ok != (want != "") {
			t.Errorf("cargoGit(%q) = %q, %v, want %q", src, got, ok, want)
		}
	}
}

// TestCargoTar stamps a tar that carries vector's cargo-sbom document and,
// for image x, a document another tool wrote. Image x's crossterm takes its
// purl from vector's copy, as fillPURLs does for any copy of a package.
func TestCargoTar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rootfs.tar")
	tarWithContent(t, path,
		[2]string{"containers/services/vector/lower/sbom.spdx.json", cargoDoc("Tool: cargo-sbom-v0.9.1")},
		[2]string{"containers/services/x/lower/sbom.spdx.json", cargoDoc("Tool: syft-1.51.0")},
		[2]string{"sbom.spdx.json", string(withCargo())})
	st, err := stampTar(path, "sbom.spdx.json", opts)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []byte
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == "sbom.spdx.json" {
			if out, err = io.ReadAll(tr); err != nil {
				t.Fatal(err)
			}
		}
	}
	var d doc
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatal(err)
	}
	type want struct{ supplier, download, purl string }
	got := map[string]want{}
	for _, p := range d.Packages {
		var w want
		w.supplier, _ = p["supplier"].(string)
		w.download, _ = p["downloadLocation"].(string)
		if refs, ok := p["externalRefs"].([]any); ok && len(refs) > 0 {
			w.purl = refs[0].(map[string]any)["referenceLocator"].(string)
		}
		got[p["SPDXID"].(string)] = w
	}
	kernelPURL := "pkg:generic/linux-kernel@6.18.55-linuxkit-core-92df24b15f57"
	for id, w := range map[string]want{
		"SPDXRef-containers-services-vector-lower-Package-crossterm-0.28.1": {"Organization: crossterm-rs", crosstermVCS,
			"pkg:cargo/crossterm@0.28.1?vcs_url=" + purlEscape(crosstermVCS)},
		"SPDXRef-containers-services-vector-lower-Package-vector-common-macros-0.1.0": {"Organization: Vector", "NOASSERTION", ""},
		"SPDXRef-containers-services-x-lower-Package-crossterm-0.28.1": {"Organization: crossterm-rs", "NOASSERTION",
			"pkg:cargo/crossterm@0.28.1?vcs_url=" + purlEscape(crosstermVCS)},
		"SPDXRef-docker.io-lfedge-eve-kernel-Package-linux-kernel-linux-kernel-1": {lfEdge,
			"git+https://github.com/lf-edge/eve-kernel@92df24b15f57", kernelPURL},
		"SPDXRef-docker.io-example-kernel-Package-linux-kernel-linux-kernel-1":     {"NOASSERTION", "NOASSERTION", kernelPURL},
		"SPDXRef-containers-services-node-exporter-lower-Package-binary-busybox-1": {"Organization: BusyBox", "NOASSERTION", "pkg:generic/busybox@1.36.1"},
	} {
		if got[id] != w {
			t.Errorf("%s: got %+v, want %+v", id, got[id], w)
		}
	}
	if st.NoSupplier != 1 || st.FilledPURLs != 1 {
		t.Errorf("stats %+v, want 1 package without supplier and 1 purl copied", st)
	}
	c := Content{Cargo: map[string]map[string]string{
		"/containers/services/vector/lower/sbom.spdx.json": cargoSources([]byte(cargoDoc("Tool: cargo-sbom-v0.9.1"))),
	}}
	if again, _, _ := Stamp(out, opts, c); !bytes.Equal(out, again) {
		t.Errorf("restamping changed the document:\n%s\n%s", out, again)
	}
}
