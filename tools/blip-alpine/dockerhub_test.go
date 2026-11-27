// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"go.podman.io/image/v5/pkg/sysregistriesv2"
)

// fakeRegistry is a container registry with the images that a test pushes
// into it. It keeps what it was asked and how much of a blob it got rid of.
type fakeRegistry struct {
	t      *testing.T
	server *httptest.Server
	// token is what the registry wants to be shown by whoever reads from
	// it, the way Docker Hub does. Everybody gets it at /token, but who logs
	// in for it there is refused, as with a wrong password. A registry
	// without one asks for nothing.
	token string

	mu        sync.Mutex
	manifests map[string]v1.Descriptor // by repository:tag and repository@digest
	blobs     map[digest.Digest][]byte // manifests too
	requests  []string                 // as in "GET /v2/lfedge/eve-alpine/manifests/3.22"
	sent      map[digest.Digest]int64  // bytes of a blob that the last request for it took
	sending   int                      // blobs that are on their way to somebody
}

// newFakeRegistry starts a registry and makes the library that pulls images
// accept it for the time of the test: its certificate is one that nobody
// trusts, so it is entered as an insecure registry, the way a user would do
// it for a registry of their own. The logins of the user who runs the test
// are kept out of it.
func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	f := &fakeRegistry{
		t:         t,
		manifests: map[string]v1.Descriptor{},
		blobs:     map[digest.Digest][]byte{},
		sent:      map[digest.Digest]int64{},
	}
	f.server = httptest.NewUnstartedServer(f)
	// the server would report every connection that the client opened in
	// advance and that is cut off when the test is over
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.server.StartTLS()
	t.Cleanup(func() {
		// the server waits for whoever still reads from it
		f.server.CloseClientConnections()
		f.server.Close()
	})

	conf := filepath.Join(t.TempDir(), "registries.conf")
	entry := fmt.Sprintf("[[registry]]\nlocation = %q\ninsecure = true\n", f.host())
	if err := os.WriteFile(conf, []byte(entry), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTAINERS_REGISTRIES_CONF", conf)
	t.Setenv("CONTAINERS_REGISTRIES_CONF_OVERRIDE", "")
	// the library reads its configuration once and keeps it
	sysregistriesv2.InvalidateCache()
	t.Cleanup(sysregistriesv2.InvalidateCache)

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("DOCKER_CONFIG", filepath.Join(home, ".docker"))
	return f
}

// host returns the host:port that the registry is at.
func (f *fakeRegistry) host() string {
	return strings.TrimPrefix(f.server.URL, "https://")
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.mu.Unlock()

	if f.token != "" && r.URL.Path == "/token" {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"details": "incorrect username or password"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":        f.token,
			"access_token": f.token,
			"expires_in":   300,
			"issued_at":    time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	if f.token != "" && r.Header.Get("Authorization") != "Bearer "+f.token {
		w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="registry.test"`, f.server.URL))
		f.refuse(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}
	path, isAPI := strings.CutPrefix(r.URL.Path, "/v2/")
	if !isAPI || r.Method != http.MethodGet {
		f.refuse(w, http.StatusNotFound, "UNSUPPORTED", "the fake registry does not do that")
		return
	}
	if path == "" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{}")
		return
	}
	if repo, ref, ok := strings.Cut(path, "/manifests/"); ok {
		f.mu.Lock()
		desc, found := f.manifests[repo+":"+ref]
		if !found {
			desc, found = f.manifests[repo+"@"+ref]
		}
		content := f.blobs[desc.Digest]
		f.mu.Unlock()
		if !found {
			f.refuse(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest unknown")
			return
		}
		w.Header().Set("Content-Type", desc.MediaType)
		w.Header().Set("Docker-Content-Digest", desc.Digest.String())
		_, _ = w.Write(content)
		return
	}
	if _, ref, ok := strings.Cut(path, "/blobs/"); ok {
		f.mu.Lock()
		content, found := f.blobs[digest.Digest(ref)]
		f.mu.Unlock()
		if !found {
			f.refuse(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob unknown to registry")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(content)))
		f.mu.Lock()
		f.sent[digest.Digest(ref)] = 0
		f.sending++
		f.mu.Unlock()
		defer func() {
			f.mu.Lock()
			f.sending--
			f.mu.Unlock()
		}()
		for len(content) > 0 {
			n, err := w.Write(content[:min(len(content), 32<<10)])
			f.mu.Lock()
			f.sent[digest.Digest(ref)] += int64(n)
			f.mu.Unlock()
			if err != nil {
				return
			}
			content = content[n:]
		}
		return
	}
	f.refuse(w, http.StatusNotFound, "NAME_UNKNOWN", "repository name not known to registry")
}

// took returns how many bytes of a blob the one who last asked for it took,
// or what the registry could at least get rid of.
func (f *fakeRegistry) took(blob []byte) int64 {
	sum := sha256.Sum256(blob)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent[digest.Digest("sha256:"+hex.EncodeToString(sum[:]))]
}

// settled tells whether the registry is done with sending blobs: at once,
// or within the seconds that it takes to notice that nobody reads any more.
func (f *fakeRegistry) settled() bool {
	for range 500 {
		f.mu.Lock()
		sending := f.sending
		f.mu.Unlock()
		if sending == 0 {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// refuse answers the way a registry does when it does not give something out.
func (f *fakeRegistry) refuse(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]string{{"code": code, "message": message}},
	})
}

// asked returns the requests that the registry got so far.
func (f *fakeRegistry) asked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

// blob stores content in the registry and returns how a manifest refers to
// it.
func (f *fakeRegistry) blob(mediaType string, content []byte) v1.Descriptor {
	sum := sha256.Sum256(content)
	desc := v1.Descriptor{
		MediaType: mediaType,
		Digest:    digest.Digest("sha256:" + hex.EncodeToString(sum[:])),
		Size:      int64(len(content)),
	}
	f.mu.Lock()
	f.blobs[desc.Digest] = content
	f.mu.Unlock()
	return desc
}

// image stores an image that is made of the layers, the lowest one first,
// in a repository and returns how an index refers to it. The image is for
// the architecture arch and for the operating system that the test runs
// on. A layer is a tar archive, compressed or not.
func (f *fakeRegistry) image(repo, arch string, layers ...[]byte) v1.Descriptor {
	f.t.Helper()
	config := v1.Image{
		Platform: v1.Platform{Architecture: arch, OS: runtime.GOOS},
		RootFS:   v1.RootFS{Type: "layers"},
	}
	manifest := v1.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: v1.MediaTypeImageManifest,
	}
	for _, layer := range layers {
		mediaType, plain := v1.MediaTypeImageLayerGzip, layer
		if unzipped, err := gzip.NewReader(bytes.NewReader(layer)); err != nil {
			mediaType = v1.MediaTypeImageLayer
		} else if plain, err = io.ReadAll(unzipped); err != nil {
			f.t.Fatal(err)
		}
		manifest.Layers = append(manifest.Layers, f.blob(mediaType, layer))
		sum := sha256.Sum256(plain)
		config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, digest.Digest("sha256:"+hex.EncodeToString(sum[:])))
	}
	manifest.Config = f.blob(v1.MediaTypeImageConfig, f.json(config))
	desc := f.blob(v1.MediaTypeImageManifest, f.json(manifest))
	desc.Platform = &config.Platform
	f.mu.Lock()
	f.manifests[repo+"@"+desc.Digest.String()] = desc
	f.mu.Unlock()
	return desc
}

// index stores an image for more than one platform, which is a list of
// images, in a repository and returns what to tag.
func (f *fakeRegistry) index(repo string, images ...v1.Descriptor) v1.Descriptor {
	f.t.Helper()
	desc := f.blob(v1.MediaTypeImageIndex, f.json(v1.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: v1.MediaTypeImageIndex,
		Manifests: images,
	}))
	f.mu.Lock()
	f.manifests[repo+"@"+desc.Digest.String()] = desc
	f.mu.Unlock()
	return desc
}

// tag gives a manifest or an index of a repository a tag and returns the
// name to pull it by.
func (f *fakeRegistry) tag(repo, tag string, desc v1.Descriptor) string {
	f.mu.Lock()
	f.manifests[repo+":"+tag] = desc
	f.mu.Unlock()
	return f.host() + "/" + repo + ":" + tag
}

func (f *fakeRegistry) json(v any) []byte {
	f.t.Helper()
	content, err := json.Marshal(v)
	if err != nil {
		f.t.Fatal(err)
	}
	return content
}

// member is what a layer holds under a name; regular, directory and symlink
// make them.
type member struct {
	header  tar.Header
	content string
}

func regular(name, content string) member {
	return member{tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0644, Size: int64(len(content))}, content}
}

func directory(name string) member {
	return member{tar.Header{Typeflag: tar.TypeDir, Name: name, Mode: 0755}, ""}
}

func symlink(name, target string) member {
	return member{tar.Header{Typeflag: tar.TypeSymlink, Name: name, Linkname: target, Mode: 0777}, ""}
}

// tarOf returns a tar archive of the members, in their order.
func tarOf(t *testing.T, members ...member) []byte {
	t.Helper()
	var archive bytes.Buffer
	w := tar.NewWriter(&archive)
	for _, m := range members {
		if err := w.WriteHeader(&m.header); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, m.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

// layerOf returns a layer of the members the way registries mostly have them:
// a tar archive that is compressed with gzip.
func layerOf(t *testing.T, members ...member) []byte {
	t.Helper()
	var zipped bytes.Buffer
	w := gzip.NewWriter(&zipped)
	if _, err := w.Write(tarOf(t, members...)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return zipped.Bytes()
}

// readFromImage returns the content of a file of an image: all that
// extractFromDockerImage gives to read of it.
func readFromImage(image, file string) (string, error) {
	content, err := extractFromDockerImage(image, file)
	if err != nil {
		return "", err
	}
	defer content.Close()
	all, err := io.ReadAll(content)
	return string(all), err
}

func TestExtractFromDockerImage(t *testing.T) {
	t.Run("gives the file of the image to read", func(t *testing.T) {
		reg := newFakeRegistry(t)
		image := reg.tag("lfedge/eve-alpine", "3a8c6b27", reg.image("lfedge/eve-alpine", "amd64", layerOf(t,
			directory("etc/"),
			regular("etc/alpine-release", "3.22.2\n"),
			directory("mirror/"),
			directory("mirror/3.22/"),
			directory("mirror/3.22/x86_64/"),
			regular("mirror/3.22/x86_64/APKINDEX.tar.gz", "the index of the mirror\n"),
			regular("mirror/3.22/x86_64/zstd-1.5.7-r0.apk", "a package\n"),
		)))

		got, err := readFromImage(image, "/mirror/3.22/x86_64/APKINDEX.tar.gz")

		if err != nil {
			t.Fatalf("extractFromDockerImage: %v", err)
		}
		if want := "the index of the mirror\n"; got != want {
			t.Errorf("read %q, want %q", got, want)
		}
		if asked := reg.asked(); !slices.Contains(asked, "GET /v2/lfedge/eve-alpine/manifests/3a8c6b27") {
			t.Errorf("the registry was asked %q, want it asked for the tag 3a8c6b27 of lfedge/eve-alpine", asked)
		}
	})

	t.Run("takes the file as the layer on top has it", func(t *testing.T) {
		reg := newFakeRegistry(t)
		image := reg.tag("lfedge/eve-alpine", "3.22", reg.image("lfedge/eve-alpine", "amd64",
			layerOf(t, directory("etc/"), regular("etc/alpine-release", "3.22.0\n")),
			layerOf(t, directory("etc/"), regular("etc/alpine-release", "3.22.1\n")),
			layerOf(t, directory("etc/"), regular("etc/alpine-release", "3.22.2\n")),
		))

		got, err := readFromImage(image, "/etc/alpine-release")

		if err != nil {
			t.Fatalf("extractFromDockerImage: %v", err)
		}
		if want := "3.22.2\n"; got != want {
			t.Errorf("read %q, want %q", got, want)
		}
	})

	t.Run("finds a file that only a layer below has", func(t *testing.T) {
		reg := newFakeRegistry(t)
		image := reg.tag("lfedge/eve-alpine", "3.22", reg.image("lfedge/eve-alpine", "amd64",
			layerOf(t, directory("etc/"), regular("etc/alpine-release", "3.22.2\n")),
			layerOf(t, directory("etc/"), regular("etc/hostname", "eve\n")),
			layerOf(t, directory("usr/"), directory("usr/local/"), regular("usr/local/go", "the toolchain\n")),
		))

		got, err := readFromImage(image, "/etc/alpine-release")

		if err != nil {
			t.Fatalf("extractFromDockerImage: %v", err)
		}
		if want := "3.22.2\n"; got != want {
			t.Errorf("read %q, want %q", got, want)
		}
	})

	// A layer removes what the layers below it have with a whiteout: an
	// empty file whose name is that of what is removed after ".wh.". The
	// whiteout ".wh..wh..opq" removes all that the layers below have in its
	// directory.
	removals := []struct {
		what  string
		layer []member
		file  string
	}{
		{"the file", []member{directory("etc/"), regular("etc/.wh.motd", "")}, "/etc/motd"},
		{"the directory of the file", []member{regular(".wh.etc", "")}, "/etc/motd"},
		{"a directory further up", []member{directory("usr/"), regular("usr/.wh.share", "")}, "/usr/share/misc/motd"},
		{"all in the directory of the file", []member{directory("etc/"), regular("etc/.wh..wh..opq", "")}, "/etc/motd"},
		{"all in a directory further up", []member{directory("usr/"), regular("usr/.wh..wh..opq", "")}, "/usr/share/misc/motd"},
		{"all there is", []member{regular(".wh..wh..opq", "")}, "/etc/motd"},
		{"the file, with names that start with ./", []member{directory("./"), directory("./etc/"), regular("./etc/.wh.motd", "")}, "/etc/motd"},
	}
	for _, removal := range removals {
		t.Run("does not bring back a file when a layer above removed "+removal.what, func(t *testing.T) {
			reg := newFakeRegistry(t)
			image := reg.tag("lfedge/eve-alpine", "3.22", reg.image("lfedge/eve-alpine", "amd64",
				layerOf(t,
					directory("etc/"), regular("etc/motd", "Welcome to Alpine!\n"),
					directory("usr/"), directory("usr/share/"), directory("usr/share/misc/"), regular("usr/share/misc/motd", "Welcome to Alpine!\n"),
				),
				layerOf(t, removal.layer...),
				layerOf(t, directory("root/"), regular("root/.profile", "")),
			))

			got, err := readFromImage(image, removal.file)

			if err == nil || !strings.Contains(err.Error(), removal.file) {
				t.Errorf("read %q with error %v, want an error that names %s", got, err, removal.file)
			}
		})
	}

	t.Run("takes the file of a layer that replaces all in its directory", func(t *testing.T) {
		reg := newFakeRegistry(t)
		image := reg.tag("lfedge/eve-alpine", "3.22", reg.image("lfedge/eve-alpine", "amd64",
			layerOf(t, directory("etc/"), regular("etc/motd", "Welcome to Alpine!\n"), regular("etc/hostname", "alpine\n")),
			layerOf(t, directory("etc/"), regular("etc/.wh..wh..opq", ""), regular("etc/motd", "Welcome to EVE!\n")),
		))

		got, err := readFromImage(image, "/etc/motd")

		if err != nil {
			t.Fatalf("extractFromDockerImage: %v", err)
		}
		if want := "Welcome to EVE!\n"; got != want {
			t.Errorf("read %q, want %q", got, want)
		}
	})

	t.Run("keeps a file when a layer above removed others with names like its own", func(t *testing.T) {
		reg := newFakeRegistry(t)
		image := reg.tag("lfedge/eve-alpine", "3.22", reg.image("lfedge/eve-alpine", "amd64",
			layerOf(t, directory("etc/"), regular("etc/motd", "Welcome to Alpine!\n")),
			layerOf(t,
				regular(".wh.et", ""),
				regular(".wh.etc2", ""),
				directory("etc/"),
				regular("etc/.wh.mot", ""),
				regular("etc/.wh.motd.old", ""),
				directory("etc/motd.d/"),
				regular("etc/motd.d/.wh..wh..opq", ""),
				directory("usr/"),
				directory("usr/etc/"),
				regular("usr/etc/.wh.motd", ""),
				regular("usr/etc/.wh..wh..opq", ""),
			),
		))

		got, err := readFromImage(image, "/etc/motd")

		if err != nil {
			t.Fatalf("extractFromDockerImage: %v", err)
		}
		if want := "Welcome to Alpine!\n"; got != want {
			t.Errorf("read %q, want %q", got, want)
		}
	})

	t.Run("fails for a file that the image does not have", func(t *testing.T) {
		reg := newFakeRegistry(t)
		image := reg.tag("lfedge/eve-alpine", "3.22", reg.image("lfedge/eve-alpine", "amd64",
			layerOf(t, directory("etc/"), regular("etc/alpine-release", "3.22.2\n")),
			layerOf(t, directory("etc/"), regular("etc/hostname", "eve\n")),
		))

		content, err := extractFromDockerImage(image, "/etc/motd")

		if err == nil || !strings.Contains(err.Error(), "/etc/motd") || !strings.Contains(err.Error(), image) {
			t.Errorf("got error %v, want one that names /etc/motd and %s", err, image)
		}
		if content != nil {
			t.Errorf("got something to read along with the error")
		}
	})

	// Only a regular file can be read as what it is. The layer below has a
	// regular file of each name: it is not what the image has.
	others := []struct {
		what   string
		member member
		file   string
		want   string // in the error
	}{
		{"a directory", directory("etc/"), "/etc", "directory"},
		{"a directory, asked for with a / at its end", directory("etc/"), "/etc/", "directory"},
		{"a symbolic link", symlink("bin/sh", "/bin/busybox"), "/bin/sh", "/bin/busybox"},
		{"a hard link", member{tar.Header{Typeflag: tar.TypeLink, Name: "bin/sh", Linkname: "bin/busybox"}, ""}, "/bin/sh", "bin/busybox"},
		{"a device", member{tar.Header{Typeflag: tar.TypeChar, Name: "dev/null", Devmajor: 1, Devminor: 3}, ""}, "/dev/null", "special file"},
	}
	for _, other := range others {
		t.Run("refuses "+other.what, func(t *testing.T) {
			reg := newFakeRegistry(t)
			image := reg.tag("lfedge/eve-alpine", "3.22", reg.image("lfedge/eve-alpine", "amd64",
				layerOf(t, regular("etc", "once a file\n"), directory("bin/"), regular("bin/sh", "once a shell\n"), directory("dev/"), regular("dev/null", "once a file\n")),
				layerOf(t, other.member),
			))

			got, err := readFromImage(image, other.file)

			if err == nil || !strings.Contains(err.Error(), other.want) {
				t.Errorf("read %q with error %v, want an error that says %q", got, err, other.want)
			}
		})
	}

	t.Run("does not take a file from below what a layer above made a symbolic link", func(t *testing.T) {
		reg := newFakeRegistry(t)
		image := reg.tag("lfedge/eve-alpine", "3.23", reg.image("lfedge/eve-alpine", "amd64",
			layerOf(t, directory("lib/"), directory("lib/apk/"), directory("lib/apk/db/"), regular("lib/apk/db/installed", "the packages before\n")),
			layerOf(t,
				directory("usr/"), directory("usr/lib/"), directory("usr/lib/apk/"), directory("usr/lib/apk/db/"),
				regular("usr/lib/apk/db/installed", "the packages\n"),
				symlink("lib", "usr/lib"),
			),
		))

		got, err := readFromImage(image, "/lib/apk/db/installed")

		if err == nil || !strings.Contains(err.Error(), "/lib is a symbolic link to usr/lib") {
			t.Errorf("read %q with error %v, want an error that says what /lib is", got, err)
		}
	})

	t.Run("fails to read a file that the registry does not send all of", func(t *testing.T) {
		reg := newFakeRegistry(t)
		// the layer ends after the first 1000 of the 3000 bytes of the file
		whole := tarOf(t, directory("mirror/"), regular("mirror/APKINDEX.tar.gz", strings.Repeat("a package\n", 300)))
		image := reg.tag("lfedge/eve-alpine", "3.22", reg.image("lfedge/eve-alpine", "amd64", whole[:2*512+1000]))

		got, err := readFromImage(image, "/mirror/APKINDEX.tar.gz")

		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("read %d bytes with error %v, want the error of content that ends too early", len(got), err)
		}
		if !strings.Contains(err.Error(), "/mirror/APKINDEX.tar.gz") || !strings.Contains(err.Error(), image) {
			t.Errorf("got error %v, want one that names /mirror/APKINDEX.tar.gz and %s", err, image)
		}
	})

	t.Run("takes the image for the platform that it runs on", func(t *testing.T) {
		other := "riscv64"
		if runtime.GOARCH == other {
			other = "amd64"
		}
		reg := newFakeRegistry(t)
		theirs := reg.image("lfedge/eve-alpine", other, layerOf(t, directory("etc/"), regular("etc/arch", "that of others\n")))
		ours := reg.image("lfedge/eve-alpine", runtime.GOARCH, layerOf(t, directory("etc/"), regular("etc/arch", "that of this machine\n")))
		// what "docker buildx" adds to an image to say how it was built
		attestation := reg.image("lfedge/eve-alpine", "unknown", layerOf(t, regular("etc/arch", "none\n")))
		attestation.Platform = &v1.Platform{Architecture: "unknown", OS: "unknown"}
		attestation.Annotations = map[string]string{
			"vnd.docker.reference.type":   "attestation-manifest",
			"vnd.docker.reference.digest": theirs.Digest.String(),
		}
		image := reg.tag("lfedge/eve-alpine", "3.22", reg.index("lfedge/eve-alpine", theirs, attestation, ours))

		got, err := readFromImage(image, "/etc/arch")

		if err != nil {
			t.Fatalf("extractFromDockerImage: %v", err)
		}
		if want := "that of this machine\n"; got != want {
			t.Errorf("read %q, want %q", got, want)
		}
	})

	t.Run("ends the download of a layer when the file is closed", func(t *testing.T) {
		// a layer like the one of eve-alpine: the file comes early, and far
		// more than fits into the buffers of a connection comes after it
		const rest = 64 << 20
		var mirror bytes.Buffer
		mirror.Grow(rest + 8<<10)
		w := tar.NewWriter(&mirror)
		for _, m := range []member{
			directory("mirror/"),
			regular("mirror/APKINDEX.tar.gz", "the index of the mirror\n"),
			{tar.Header{Typeflag: tar.TypeReg, Name: "mirror/gcc-14.2.0-r6.apk", Mode: 0644, Size: rest}, ""},
		} {
			if err := w.WriteHeader(&m.header); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(w, m.content); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := w.Write(make([]byte, rest)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		reg := newFakeRegistry(t)
		image := reg.tag("lfedge/eve-alpine", "3.22", reg.image("lfedge/eve-alpine", "amd64", mirror.Bytes()))

		content, err := extractFromDockerImage(image, "/mirror/APKINDEX.tar.gz")
		if err != nil {
			t.Fatalf("extractFromDockerImage: %v", err)
		}
		got, err := io.ReadAll(content)
		if err != nil {
			t.Errorf("reading the file: %v", err)
		}
		if err := content.Close(); err != nil {
			t.Errorf("closing the file: %v", err)
		}

		if want := "the index of the mirror\n"; string(got) != want {
			t.Errorf("read %q, want %q", got, want)
		}
		if !reg.settled() {
			t.Errorf("the registry is still sending the layer after the file was closed")
		}
		if took := reg.took(mirror.Bytes()); took > rest/2 {
			t.Errorf("took %d of the %d bytes of the layer, want it to stop after the file", took, mirror.Len())
		}
	})

	t.Run("can be closed more than once", func(t *testing.T) {
		reg := newFakeRegistry(t)
		image := reg.tag("lfedge/eve-alpine", "3.22", reg.image("lfedge/eve-alpine", "amd64",
			layerOf(t, directory("etc/"), regular("etc/alpine-release", "3.22.2\n")),
		))
		content, err := extractFromDockerImage(image, "/etc/alpine-release")
		if err != nil {
			t.Fatalf("extractFromDockerImage: %v", err)
		}

		for range 3 {
			if err := content.Close(); err != nil {
				t.Errorf("closing the file: %v", err)
			}
		}
	})

	t.Run("finds the file whichever way its name is written", func(t *testing.T) {
		reg := newFakeRegistry(t)
		image := reg.tag("lfedge/eve-alpine", "3.22", reg.image("lfedge/eve-alpine", "amd64",
			layerOf(t, directory("etc/"), regular("etc/alpine-release", "3.22.2\n")),
			layerOf(t, directory("./"), directory("./etc/"), regular("./etc/hostname", "eve\n")),
			layerOf(t, directory("/etc/"), regular("/etc/motd", "Welcome to EVE!\n")),
		))
		names := map[string]string{
			"/etc/alpine-release":         "3.22.2\n",
			"etc/alpine-release":          "3.22.2\n",
			"./etc/alpine-release":        "3.22.2\n",
			"//etc/./alpine-release":      "3.22.2\n",
			"/etc/apk/../alpine-release":  "3.22.2\n",
			"/../../etc/alpine-release":   "3.22.2\n",
			"/etc/hostname":               "eve\n",
			"etc/hostname":                "eve\n",
			"/etc/motd":                   "Welcome to EVE!\n",
			"etc/motd":                    "Welcome to EVE!\n",
			"./etc/motd":                  "Welcome to EVE!\n",
			"etc/../../../../../etc/motd": "Welcome to EVE!\n",
		}
		for name, want := range names {
			got, err := readFromImage(image, name)

			if err != nil {
				t.Errorf("%s: extractFromDockerImage: %v", name, err)
			} else if got != want {
				t.Errorf("%s: read %q, want %q", name, got, want)
			}
		}
	})

	t.Run("asks the registry for nothing when no file is named", func(t *testing.T) {
		reg := newFakeRegistry(t)
		image := reg.tag("lfedge/eve-alpine", "3.22", reg.image("lfedge/eve-alpine", "amd64",
			layerOf(t, directory("./"), directory("./etc/"), regular("./etc/alpine-release", "3.22.2\n")),
		))
		for _, name := range []string{"", "/", ".", "./", "..", "/../..", "/etc/.."} {
			got, err := readFromImage(image, name)

			if err == nil {
				t.Errorf("%q: read %q, want an error", name, got)
			}
		}
		if asked := reg.asked(); len(asked) != 0 {
			t.Errorf("the registry was asked %q, want nothing", asked)
		}
	})

	t.Run("fails for an image that the registry does not have", func(t *testing.T) {
		reg := newFakeRegistry(t)
		reg.tag("lfedge/eve-alpine", "8c9af556", reg.image("lfedge/eve-alpine", "amd64",
			layerOf(t, directory("etc/"), regular("etc/alpine-release", "3.22.2\n")),
		))
		image := reg.host() + "/lfedge/eve-alpine:3a8c6b27"

		got, err := readFromImage(image, "/etc/alpine-release")

		if err == nil || !strings.Contains(err.Error(), image) {
			t.Errorf("read %q with error %v, want an error that names %s", got, err, image)
		}
	})

	t.Run("reads what all may read without a login, whatever logins the user has", func(t *testing.T) {
		reg := newFakeRegistry(t)
		reg.token = "for-all-who-ask"
		image := reg.tag("lfedge/eve-alpine", "3.22", reg.image("lfedge/eve-alpine", "amd64",
			layerOf(t, directory("etc/"), regular("etc/alpine-release", "3.22.2\n")),
		))
		// a login as the docker command keeps it, which the registry refuses
		login := base64.StdEncoding.EncodeToString([]byte("eve:outdated"))
		config := fmt.Sprintf(`{"auths": {%q: {"auth": %q}}}`, reg.host(), login)
		if err := os.MkdirAll(os.Getenv("DOCKER_CONFIG"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(os.Getenv("DOCKER_CONFIG"), "config.json"), []byte(config), 0600); err != nil {
			t.Fatal(err)
		}

		got, err := readFromImage(image, "/etc/alpine-release")

		if err != nil {
			t.Fatalf("extractFromDockerImage: %v", err)
		}
		if want := "3.22.2\n"; got != want {
			t.Errorf("read %q, want %q", got, want)
		}
	})
}
