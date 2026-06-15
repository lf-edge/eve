// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package zboot

import (
	"fmt"
	"testing"

	"github.com/lf-edge/edge-containers/pkg/registry"
	"github.com/lf-edge/eve/pkg/pillar/cas"
)

// fakeCAS embeds cas.CAS so only GetImageLayers needs a real implementation;
// any other call panics via the nil embedded interface.
type fakeCAS struct {
	cas.CAS
	layers []cas.ImageLayer
	err    error
}

func (f *fakeCAS) GetImageLayers(string) ([]cas.ImageLayer, error) {
	return f.layers, f.err
}

func rootDisk(size int64) cas.ImageLayer {
	return cas.ImageLayer{Size: size, Annotations: map[string]string{registry.AnnotationRole: registry.RoleRootDisk}}
}

func extDisk(size int64) cas.ImageLayer {
	return cas.ImageLayer{Size: size, Annotations: map[string]string{registry.AnnotationRole: "disk-1"}}
}

func TestDiskRootLayerSize(t *testing.T) {
	const wantSize = int64(268435456) // ~256 MB Core rootfs

	tests := []struct {
		name      string
		layers    []cas.ImageLayer
		err       error
		wantSize  int64
		wantFound bool
		wantErr   bool
	}{
		{
			name:      "split-rootfs: pick disk-root, ignore extension",
			layers:    []cas.ImageLayer{rootDisk(wantSize), extDisk(1503564288)},
			wantSize:  wantSize,
			wantFound: true,
		},
		{
			name:      "single raw image wrapped as disk-root",
			layers:    []cas.ImageLayer{rootDisk(wantSize)},
			wantSize:  wantSize,
			wantFound: true,
		},
		{
			name:      "no disk-root layer",
			layers:    []cas.ImageLayer{extDisk(123)},
			wantFound: false,
		},
		{
			name:    "CAS error",
			err:     fmt.Errorf("boom"),
			wantErr: true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeCAS{layers: tc.layers, err: tc.err}
			size, found, err := diskRootLayerSize(f, "ref")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if found != tc.wantFound || size != tc.wantSize {
				t.Fatalf("got size=%d found=%v, want %d/%v", size, found, tc.wantSize, tc.wantFound)
			}
		})
	}
}
