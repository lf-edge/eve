// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"
)

// bootFile is one file of the boot image: its path in the image and
// the host file it is copied from.
type bootFile struct {
	name string
	src  string
}

// bootFiles are what KubeVirt's kernelBoot container image must hold:
// the host kernel and the initrd of the VMs container apps run in,
// the same pair pillar boots container apps with on HV=kvm.
var bootFiles = []bootFile{
	{name: "kernel", src: BootKernel},
	{name: "runx-initrd", src: BootInitrd},
}

// writeBootImageArchive writes a docker-archive (`docker save`
// format) of a single-layer image holding files, tagged repoTag,
// for runtime.GOARCH. The archive depends only on its inputs: every
// tar entry has a zero mtime and owner, and the JSON is emitted from
// fixed structs, so the same files always yield the same image
// digest. Returns the layer's diff ID.
func writeBootImageArchive(w io.Writer, files []bootFile, repoTag string) (string, error) {
	h := sha256.New()
	var size countingWriter
	if err := writeLayer(io.MultiWriter(h, &size), files); err != nil {
		return "", err
	}
	diffID := "sha256:" + hex.EncodeToString(h.Sum(nil))

	config, err := json.Marshal(imageConfig{
		Architecture: runtime.GOARCH,
		OS:           "linux",
		RootFS:       rootFS{Type: "layers", DiffIDs: []string{diffID}},
	})
	if err != nil {
		return "", err
	}
	configSum := sha256.Sum256(config)
	configName := hex.EncodeToString(configSum[:]) + ".json"
	layerName := diffID[len("sha256:"):] + "/layer.tar"
	manifest, err := json.Marshal([]archiveManifest{{
		Config:   configName,
		RepoTags: []string{repoTag},
		Layers:   []string{layerName},
	}})
	if err != nil {
		return "", err
	}

	tw := tar.NewWriter(w)
	if err := writeEntry(tw, configName, int64(len(config))); err != nil {
		return "", err
	}
	if _, err := tw.Write(config); err != nil {
		return "", err
	}
	if err := writeEntry(tw, layerName, int64(size)); err != nil {
		return "", err
	}
	if err := writeLayer(tw, files); err != nil {
		return "", err
	}
	if err := writeEntry(tw, "manifest.json", int64(len(manifest))); err != nil {
		return "", err
	}
	if _, err := tw.Write(manifest); err != nil {
		return "", err
	}
	return diffID, tw.Close()
}

// imageConfig, rootFS and archiveManifest are the fields of the image
// config and of the docker-archive manifest.json that containerd's
// importer needs.
type imageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	RootFS       rootFS `json:"rootfs"`
}

type rootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

type archiveManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// writeLayer writes the layer tarball of files to w. It is called
// twice per archive, once to hash the layer and once to write it, so
// the layer is never held in memory or in a temporary file.
func writeLayer(w io.Writer, files []bootFile) error {
	tw := tar.NewWriter(w)
	for _, f := range files {
		if err := copyFile(tw, f); err != nil {
			return err
		}
	}
	return tw.Close()
}

func copyFile(tw *tar.Writer, f bootFile) error {
	in, err := os.Open(f.src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if err := writeEntry(tw, f.name, st.Size()); err != nil {
		return err
	}
	n, err := io.Copy(tw, in)
	if err != nil {
		return err
	}
	if n != st.Size() {
		return fmt.Errorf("%s changed size while being read", f.src)
	}
	return nil
}

type countingWriter int64

func (c *countingWriter) Write(p []byte) (int, error) {
	*c += countingWriter(len(p))
	return len(p), nil
}

// writeEntry writes the header of a regular file, mode 0666 as
// pkg/external-boot-image copied them, owned by root, with the Unix
// epoch as its time.
func writeEntry(tw *tar.Writer, name string, size int64) error {
	return tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Mode:     0o666,
		Size:     size,
		ModTime:  time.Unix(0, 0),
		Format:   tar.FormatUSTAR,
	})
}
