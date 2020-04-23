// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
)

const imageConfig = `
{
    "created": "2020-04-21T00:39:14.5857389Z",
    "architecture": "amd64",
    "os": "linux",
    "config": {
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "Cmd": [
            "/bin/sh",
            "-c",
            "/runme.sh"
        ]
    },
    "rootfs": {
        "type": "layers",
        "diff_ids": [
            "sha256:beee9f30bc1f711043e78d4a2be0668955d4b761d587d6f60c2c8dc081efb203",
            "sha256:2aee9ebb1000a3f178b7354e3b908016995d49933ef55611faa14c44ec6ad5f3"
        ]
    },
    "history": [
        {
            "created": "2020-03-23T21:19:34.027725872Z",
            "created_by": "/bin/sh -c #(nop) ADD file:0c4555f363c2672e350001f1293e689875a3760afe7b3f9146886afe67121cba in / "
        },
        {
            "created": "2020-03-23T21:19:34.196162891Z",
            "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
            "empty_layer": true
        },
        {
            "created": "2020-04-21T00:39:14.4357591Z",
            "created_by": "/bin/sh -c #(nop) COPY file:460e7e85dc47719c898d4bccd36051f5010ecc18b7d0bcb627d19ada0321099a in / "
        },
        {
            "created": "2020-04-21T00:39:14.5857389Z",
            "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/sh\" \"-c\" \"/runme.sh\"]",
            "empty_layer": true
        }
    ]
}
`

func TestOciSpec(t *testing.T) {
	if err := InitContainerdClient(); err != nil {
		t.Logf("failed to init containerd client %v", err)
	}

	spec, err := NewOciSpec("test")
	if err != nil {
		t.Errorf("failed to create default OCI spec %v", err)
	}

	tmpfile, err := ioutil.TempFile("/tmp", "oci_spec*.json")
	if err != nil {
		t.Errorf("failed to create tmpfile %v", err)
	} else {
		defer os.Remove(tmpfile.Name())
	}
	tmpdir, err := ioutil.TempDir("/tmp", "volume")
	if err != nil {
		t.Errorf("failed to create tmpdir %v", err)
	} else {
		defer os.RemoveAll(tmpdir)
	}
	if ioutil.WriteFile(tmpdir+"/image-config.json", []byte(imageConfig), 0777) != nil {
		t.Errorf("failed to write to temp file %s", tmpdir+"/image-config.json")
	}

	spec.UpdateFromDomain(types.DomainConfig{VmConfig: types.VmConfig{Memory: 1234, VCpus: 4}})
	spec.UpdateFromVolume(tmpdir)

	if err := spec.Save(tmpfile); err != nil {
		t.Errorf("failed to save OCI spec file %s %v", tmpfile.Name(), err)
	}

	tmpfile.Seek(0, 0)
	if err := spec.Load(tmpfile); err != nil {
		t.Errorf("failed to load OCI spec file from file %s %v", tmpfile.Name(), err)
	}

	assert.Equal(t, *spec.Linux.Resources.Memory.Limit, int64(1234*1024),
		"Got incorrect memory limit")
	assert.Equal(t, float64(*spec.Linux.Resources.CPU.Quota)/float64(*spec.Linux.Resources.CPU.Period), float64(4),
		"Got incorrect CPU limit")
	assert.Equal(t, spec.Root.Path, "/var"+tmpdir+"/rootfs",
		"Got incorrect rootfs")
	assert.Equal(t, spec.Process.Env, []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		"Got incorrect ENV")
	assert.Equal(t, spec.Process.Args, []string{"/bin/sh", "-c", "/runme.sh"},
		"Got incorrect cmd")
}
