// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"fmt"
	uuid "github.com/satori/go.uuid"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
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

	client := &Client{}
	spec, err := client.NewOciSpec("test")
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

	conf := &types.DomainConfig{
		VmConfig: types.VmConfig{Memory: 1234, VCpus: 4},
		VifList: []types.VifInfo{
			{Vif: "vif0", Bridge: "br0", Mac: "52:54:00:12:34:56", VifUsed: "vif0-ctr"},
			{Vif: "vif1", Bridge: "br0", Mac: "52:54:00:12:34:57", VifUsed: "vif1-ctr"},
		},
	}
	spec.UpdateFromDomain(conf)
	spec.UpdateVifList(conf.VifList)
	spec.UpdateFromVolume(tmpdir)

	if err := spec.Save(tmpfile); err != nil {
		t.Errorf("failed to save OCI spec file %s %v", tmpfile.Name(), err)
	}

	tmpfile.Seek(0, 0)
	if err := spec.Load(tmpfile); err != nil {
		t.Errorf("failed to load OCI spec file from file %s %v", tmpfile.Name(), err)
	}

	s := spec.Get()
	assert.Equal(t, int64(1234*1024), *s.Linux.Resources.Memory.Limit)
	assert.Equal(t, float64(4), float64(*s.Linux.Resources.CPU.Quota)/float64(*s.Linux.Resources.CPU.Period))
	assert.Equal(t, tmpdir+"/rootfs", s.Root.Path)
	assert.Equal(t, []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}, s.Process.Env)
	assert.Equal(t, []string{"/bin/sh", "-c", "/runme.sh"}, s.Process.Args)
	assert.Equal(t, []string{"VIF_NAME=vif0", "VIF_BRIDGE=br0", "VIF_MAC=52:54:00:12:34:56"}, s.Hooks.Prestart[0].Env)
	assert.Equal(t, []string{"VIF_NAME=vif1", "VIF_BRIDGE=br0", "VIF_MAC=52:54:00:12:34:57"}, s.Hooks.Prestart[1].Env)
	assert.Equal(t, []string{"VIF_NAME=vif0", "VIF_BRIDGE=br0", "VIF_MAC=52:54:00:12:34:56"}, s.Hooks.Poststop[0].Env)
	assert.Equal(t, "/bin/eve", s.Hooks.Poststop[1].Path)
	assert.Equal(t, []string{"eve", "exec", "pillar", "/opt/zededa/bin/veth.sh", "up", "vif0", "br0", "52:54:00:12:34:56"}, s.Hooks.Prestart[0].Args)
	assert.Equal(t, []string{"eve", "exec", "pillar", "/opt/zededa/bin/veth.sh", "down", "vif1"}, s.Hooks.Poststop[1].Args)
	assert.Equal(t, 60, *s.Hooks.Poststop[1].Timeout)
}

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
        },
        "WorkingDir": "/data"
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
	podPath := path.Join(dir, imageConfigFilename)
	err := os.MkdirAll(rootDir, 0777)
	if err != nil {
		t.Errorf("failed to create temporary dir")
	} else {
		defer os.RemoveAll(dir)
	}

	// now create a fake pod file...
	if err := ioutil.WriteFile(podPath, []byte(content), 0644); err != nil {
		t.Errorf("failed to write to a pod file %v", err)
	}

	_ = InitContainerdClient()
	spec, err := NewOciSpec("test")
	if err != nil {
		t.Errorf("failed to create new OCI spec %v", err)
	}
	if err := spec.UpdateFromVolume(dir); err != nil {
		t.Errorf("failed to load OCI image spec %v", err)
	}
	spec.UpdateMounts([]types.DiskStatus{
		{FileLocation: "/foo/baz.qcow2", Format: zconfig.Format_QCOW2},
		{FileLocation: "/foo/bar", Format: zconfig.Format_CONTAINER}})
	spec.Get().Root.Path = rootDir
	if err != nil {
		t.Errorf("createMountPointExecEnvFiles failed %v", err)
	}

	execpathStr := "\"/bin/sh\""
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

func TestPrepareMount(t *testing.T) {
	imageConfig := `{
    "created": "2020-03-23T12:23:53.387962759Z",
    "author": "adarsh@zededa.com",
    "architecture": "amd64",
    "os": "linux",
    "config": {
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "Entrypoint": [
            "/start.sh"
        ],
        "Volumes": {
            "/myvol": {}
        },
        "WorkingDir": "/"
    },
    "rootfs": {
        "type": "layers",
        "diff_ids": [
            "sha256:a79a1aaf8143bbbe6061bc5326a1dcc490d9b9c1ea6b9c27d14c182e15c535ee",
            "sha256:417229adb81f0bd48fbbe7502729d98bd6d4b21e56f8ec5c71fac19487fc0815",
            "sha256:44dfb9781d0b1f0e04a50d3e4c4ce367a2b1fe15e738a70d80d7e4efd33fe35a",
            "sha256:30a4ab83cf0d257402dbb865fba2587668144cea726079265070b87783e3a54a"
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
            "created": "2020-03-23T06:11:44.080461696Z",
            "created_by": "/bin/sh -c #(nop)  MAINTAINER adarsh@zededa.com",
            "author": "adarsh@zededa.com",
            "empty_layer": true
        },
        {
            "created": "2020-03-23T06:11:45.292483419Z",
            "created_by": "/bin/sh -c mkdir /myvol",
            "author": "adarsh@zededa.com"
        },
        {
            "created": "2020-03-23T06:11:45.56347645Z",
            "created_by": "/bin/sh -c #(nop)  VOLUME [/myvol]",
            "author": "adarsh@zededa.com",
            "empty_layer": true
        },
        {
            "created": "2020-03-23T12:23:51.586264751Z",
            "created_by": "/bin/sh -c #(nop) ADD file:9f0a0ddf8a6c36f4722777c3ed02eb16ac49991ae4cee91bceae40e21794b0b6 in / ",
            "author": "adarsh@zededa.com"
        },
        {
            "created": "2020-03-23T12:23:52.762589559Z",
            "created_by": "/bin/sh -c adduser -D -g '' alpine",
            "author": "adarsh@zededa.com"
        },
        {
            "created": "2020-03-23T12:23:53.085220535Z",
            "created_by": "/bin/sh -c #(nop) WORKDIR /",
            "author": "adarsh@zededa.com",
            "empty_layer": true
        },
        {
            "created": "2020-03-23T12:23:53.387962759Z",
            "created_by": "/bin/sh -c #(nop)  ENTRYPOINT [\"/start.sh\"]",
            "author": "adarsh@zededa.com",
            "empty_layer": true
        }
    ]
}`

	err := os.MkdirAll(path.Join(oldTempRootPath, "tmp"), 0777)
	if err != nil {
		t.Errorf("TestPrepareMount: Failed to create %s: %s", oldTempRootPath, err.Error())
	} else {
		defer os.RemoveAll(oldTempRootPath)
	}

	filename := filepath.Join(oldTempRootPath, imageConfigFilename)
	if err := ioutil.WriteFile(filename, []byte(imageConfig), 0644); err != nil {
		t.Errorf("TestPrepareMount: exception while saving %s: %s", filename, err.Error())
	}

	type args struct {
		containerID   uuid.UUID
		containerPath string
		envVars       map[string]string
		noOfDisks     int
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "TestPrepareMount1",
			args: args{
				containerID:   containerID,
				containerPath: oldTempRootPath,
				envVars: map[string]string{
					"ENV1": "VAL1",
				},
				noOfDisks: 2,
			},
			wantErr: nil,
		},
		{
			name: "TestPrepareMount2",
			args: args{
				containerID:   containerID,
				containerPath: oldTempRootPath,
				envVars: map[string]string{
					"ENV1": "VAL1",
				},
				noOfDisks: 1,
			},
			wantErr: fmt.Errorf("createMountPointExecEnvFiles: Number of volumes provided: 0 is less than number of mount-points: 1. "),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = InitContainerdClient()
			spec, err := NewOciSpec("test")
			if err != nil {
				t.Errorf("failed to create new OCI spec")
			}
			if err := spec.UpdateFromVolume(oldTempRootPath); err != nil {
				t.Errorf("failed to load OCI image spec")
			}
			spec.UpdateEnvVar(tt.args.envVars)
			spec.UpdateMounts([]types.DiskStatus{
				{FileLocation: "/foo/baz.qcow2", Format: zconfig.Format_QCOW2},
				{FileLocation: "/foo/bar", Format: zconfig.Format_CONTAINER}})
			spec.Get().Root.Path = oldTempRootPath
			if err := spec.UpdateFromVolume(filepath.Join(oldTempRootPath, "tmp")); err != nil || tt.wantErr != nil {
				if (tt.wantErr == nil) || ((err != nil) && (tt.wantErr.Error() != err.Error())) {
					t.Errorf("PrepareMount() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				cmdlineFile := path.Join(tt.args.containerPath, "cmdline")
				expectedCmdLine := "\"/start.sh\""
				cmdline, err := ioutil.ReadFile(cmdlineFile)
				if err != nil {
					t.Errorf("TestPrepareMount: exception while reading cmdline file %s %v", cmdlineFile, err)
				}
				if string(cmdline) != expectedCmdLine {
					t.Errorf("TestPrepareMount: mismatched cmdline file content, actual '%s' expected '%s'",
						string(cmdline), expectedCmdLine)
				}

				mountFile := path.Join(tt.args.containerPath, "mountPoints")
				expectedMounts := "/myvol" + "\n"
				mounts, err := ioutil.ReadFile(mountFile)
				if err != nil {
					t.Errorf("TestPrepareMount: exception while reading mountPoints file %s %v", mountFile, err)
				}
				if string(mounts) != expectedMounts {
					t.Errorf("TestPrepareMount: mismatched mountpoints file content, actual '%s' expected '%s'",
						string(mounts), expectedMounts)
				}

				envFile := path.Join(tt.args.containerPath, "environment")
				expectedEnv := "export WORKDIR=\"/\"\n" +
					"export PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n" +
					"export ENV1=\"VAL1\"\n"
				env, err := ioutil.ReadFile(envFile)
				if err != nil {
					t.Errorf("TestPrepareMount: exception while reading environment file %s %v", envFile, err)
				}
				if string(env) != expectedEnv {
					t.Errorf("TestPrepareMount: mismatched environment file content, actual '%s' expected '%s'",
						string(env), expectedEnv)
				}
			}
		})
	}
}