// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage Xen guest domains based on the subscribed collection of DomainConfig
// and publish the result in a collection of DomainStatus structs.
// We run a separate go routine for each domU to be able to boot and halt
// them concurrently and also pick up their state periodically.

package containerd

import (
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func TestCreateMountPointExecEnvFiles(t *testing.T) {

	content := `{
    "created": "2020-02-05T00:52:57.387773144Z",
    "author": "adarsh@zededa.com",
    "architecture": "amd64",
    "os": "linux",
    "config": {
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "Cmd": [
            "/bin/sh"
        ],
        "Volumes": {
            "/myvol": {}
        }
    },
    "rootfs": {
        "type": "layers",
        "diff_ids": [
            "sha256:a79a1aaf8143bbbe6061bc5326a1dcc490d9b9c1ea6b9c27d14c182e15c535ee",
            "sha256:a235ff03ae531a929c240688c52e802c4f3714b2446d1f34b1d20bfd59ce1965"
        ]
    },
    "history": [
        {
            "created": "2019-01-30T22:20:20.383667418Z",
            "created_by": "/bin/sh -c #(nop) ADD file:eaf29f2198d25cc0e88b84af6478f422db6a8ffb6919bf746117252cfcd88a47 in / "
        },
        {
            "created": "2019-01-30T22:20:20.590559734Z",
            "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
            "empty_layer": true
        },
        {
            "created": "2020-02-05T00:52:55.559839255Z",
            "created_by": "/bin/sh -c #(nop)  MAINTAINER adarsh@zededa.com",
            "author": "adarsh@zededa.com",
            "empty_layer": true
        },
        {
            "created": "2020-02-05T00:52:57.115531308Z",
            "created_by": "/bin/sh -c mkdir /myvol",
            "author": "adarsh@zededa.com"
        },
        {
            "created": "2020-02-05T00:52:57.387773144Z",
            "created_by": "/bin/sh -c #(nop)  VOLUME [/myvol]",
            "author": "adarsh@zededa.com",
            "empty_layer": true
        }
    ]
}`
	//create a temp dir to hold resulting files
	dir, _ := ioutil.TempDir("/tmp", "podfiles")
	rootDir := path.Join(dir, "runx")
	podPath := path.Join(dir, "pod")
	err := os.MkdirAll(rootDir, 0777)
	if err != nil {
		t.Errorf("failed to create temporary dir")
	} else {
		defer os.RemoveAll(dir)
	}

	// now create a fake pod file
	file, _ := os.Create(podPath)
	_, err = file.WriteString(content)
	if err != nil {
		t.Errorf("failed to write to a pod file")
	}
	execpath := []string{"/bin/sh"}
	// the proper format for this
	execpathStr := "\"/bin/sh\""
	workdir := "/data"
	mountpoints := map[string]struct{}{
		"/myvol": {},
	}
	env := []string{"PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\""}

	err = createMountPointExecEnvFiles(rootDir, mountpoints, execpath, workdir, env, 2)
	if err != nil {
		t.Errorf("createMountPointExecEnvFiles failed %v", err)
	}

	cmdlineFile := path.Join(rootDir, "cmdline")
	cmdline, err := ioutil.ReadFile(cmdlineFile)
	if err != nil {
		t.Errorf("createMountPointExecEnvFiles failed to create cmdline file %s %v", cmdlineFile, err)
	}
	if string(cmdline) != execpathStr {
		t.Errorf("mismatched cmdline file content, actual '%s' expected '%s'", string(cmdline), execpathStr)
	}

	mountFile := path.Join(rootDir, "mountPoints")
	mountExpected := "/myvol" + "\n"
	mounts, err := ioutil.ReadFile(mountFile)
	if err != nil {
		t.Errorf("createMountPointExecEnvFiles failed to create mountPoints file %s %v", mountFile, err)
	}
	if string(mounts) != mountExpected {
		t.Errorf("mismatched mountpoints file content, actual '%s' expected '%s'", string(mounts), mountExpected)
	}

	envFile := path.Join(rootDir, "environment")
	envActual, err := ioutil.ReadFile(envFile)
	// start with WORKDIR
	envExpect := "export WORKDIR=\"/data\"\nexport PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n"
	if err != nil {
		t.Errorf("createMountPointExecEnvFiles failed to create environment file %s %v", envFile, err)
	}
	if string(envActual) != envExpect {
		t.Errorf("mismatched env file content, actual '%s' expected '%s'", string(envActual), envExpect)
	}
}
