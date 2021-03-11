// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"testing"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	. "github.com/onsi/gomega"
	"github.com/opencontainers/runtime-spec/specs-go"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

const loaderRuntimeSpec = `
{
    "ociVersion": "1.0.1",
    "process": {
        "user": {
            "uid": 0,
            "gid": 0
        },
        "args": [
            "/init.sh"
        ],
        "env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "cwd": "/",
        "capabilities": {
            "bounding": [
                "CAP_AUDIT_CONTROL",
                "CAP_AUDIT_READ",
                "CAP_AUDIT_WRITE",
                "CAP_BLOCK_SUSPEND",
                "CAP_CHOWN",
                "CAP_DAC_OVERRIDE",
                "CAP_DAC_READ_SEARCH",
                "CAP_FOWNER",
                "CAP_FSETID",
                "CAP_IPC_LOCK",
                "CAP_IPC_OWNER",
                "CAP_KILL",
                "CAP_LEASE",
                "CAP_LINUX_IMMUTABLE",
                "CAP_MAC_ADMIN",
                "CAP_MAC_OVERRIDE",
                "CAP_MKNOD",
                "CAP_NET_ADMIN",
                "CAP_NET_BIND_SERVICE",
                "CAP_NET_BROADCAST",
                "CAP_NET_RAW",
                "CAP_SETFCAP",
                "CAP_SETGID",
                "CAP_SETPCAP",
                "CAP_SETUID",
                "CAP_SYSLOG",
                "CAP_SYS_ADMIN",
                "CAP_SYS_BOOT",
                "CAP_SYS_CHROOT",
                "CAP_SYS_MODULE",
                "CAP_SYS_NICE",
                "CAP_SYS_PACCT",
                "CAP_SYS_PTRACE",
                "CAP_SYS_RAWIO",
                "CAP_SYS_RESOURCE",
                "CAP_SYS_TIME",
                "CAP_SYS_TTY_CONFIG",
                "CAP_WAKE_ALARM"
            ],
            "effective": [
                "CAP_AUDIT_CONTROL",
                "CAP_AUDIT_READ",
                "CAP_AUDIT_WRITE",
                "CAP_BLOCK_SUSPEND",
                "CAP_CHOWN",
                "CAP_DAC_OVERRIDE",
                "CAP_DAC_READ_SEARCH",
                "CAP_FOWNER",
                "CAP_FSETID",
                "CAP_IPC_LOCK",
                "CAP_IPC_OWNER",
                "CAP_KILL",
                "CAP_LEASE",
                "CAP_LINUX_IMMUTABLE",
                "CAP_MAC_ADMIN",
                "CAP_MAC_OVERRIDE",
                "CAP_MKNOD",
                "CAP_NET_ADMIN",
                "CAP_NET_BIND_SERVICE",
                "CAP_NET_BROADCAST",
                "CAP_NET_RAW",
                "CAP_SETFCAP",
                "CAP_SETGID",
                "CAP_SETPCAP",
                "CAP_SETUID",
                "CAP_SYSLOG",
                "CAP_SYS_ADMIN",
                "CAP_SYS_BOOT",
                "CAP_SYS_CHROOT",
                "CAP_SYS_MODULE",
                "CAP_SYS_NICE",
                "CAP_SYS_PACCT",
                "CAP_SYS_PTRACE",
                "CAP_SYS_RAWIO",
                "CAP_SYS_RESOURCE",
                "CAP_SYS_TIME",
                "CAP_SYS_TTY_CONFIG",
                "CAP_WAKE_ALARM"
            ],
            "inheritable": [
                "CAP_AUDIT_CONTROL",
                "CAP_AUDIT_READ",
                "CAP_AUDIT_WRITE",
                "CAP_BLOCK_SUSPEND",
                "CAP_CHOWN",
                "CAP_DAC_OVERRIDE",
                "CAP_DAC_READ_SEARCH",
                "CAP_FOWNER",
                "CAP_FSETID",
                "CAP_IPC_LOCK",
                "CAP_IPC_OWNER",
                "CAP_KILL",
                "CAP_LEASE",
                "CAP_LINUX_IMMUTABLE",
                "CAP_MAC_ADMIN",
                "CAP_MAC_OVERRIDE",
                "CAP_MKNOD",
                "CAP_NET_ADMIN",
                "CAP_NET_BIND_SERVICE",
                "CAP_NET_BROADCAST",
                "CAP_NET_RAW",
                "CAP_SETFCAP",
                "CAP_SETGID",
                "CAP_SETPCAP",
                "CAP_SETUID",
                "CAP_SYSLOG",
                "CAP_SYS_ADMIN",
                "CAP_SYS_BOOT",
                "CAP_SYS_CHROOT",
                "CAP_SYS_MODULE",
                "CAP_SYS_NICE",
                "CAP_SYS_PACCT",
                "CAP_SYS_PTRACE",
                "CAP_SYS_RAWIO",
                "CAP_SYS_RESOURCE",
                "CAP_SYS_TIME",
                "CAP_SYS_TTY_CONFIG",
                "CAP_WAKE_ALARM"
            ],
            "permitted": [
                "CAP_AUDIT_CONTROL",
                "CAP_AUDIT_READ",
                "CAP_AUDIT_WRITE",
                "CAP_BLOCK_SUSPEND",
                "CAP_CHOWN",
                "CAP_DAC_OVERRIDE",
                "CAP_DAC_READ_SEARCH",
                "CAP_FOWNER",
                "CAP_FSETID",
                "CAP_IPC_LOCK",
                "CAP_IPC_OWNER",
                "CAP_KILL",
                "CAP_LEASE",
                "CAP_LINUX_IMMUTABLE",
                "CAP_MAC_ADMIN",
                "CAP_MAC_OVERRIDE",
                "CAP_MKNOD",
                "CAP_NET_ADMIN",
                "CAP_NET_BIND_SERVICE",
                "CAP_NET_BROADCAST",
                "CAP_NET_RAW",
                "CAP_SETFCAP",
                "CAP_SETGID",
                "CAP_SETPCAP",
                "CAP_SETUID",
                "CAP_SYSLOG",
                "CAP_SYS_ADMIN",
                "CAP_SYS_BOOT",
                "CAP_SYS_CHROOT",
                "CAP_SYS_MODULE",
                "CAP_SYS_NICE",
                "CAP_SYS_PACCT",
                "CAP_SYS_PTRACE",
                "CAP_SYS_RAWIO",
                "CAP_SYS_RESOURCE",
                "CAP_SYS_TIME",
                "CAP_SYS_TTY_CONFIG",
                "CAP_WAKE_ALARM"
            ]
        }
    },
    "root": {
        "path": "rootfs"
    },
    "mounts": [
        {
            "destination": "/dev",
            "type": "bind",
            "source": "/dev",
            "options": [
                "rw",
                "rbind",
                "rshared"
            ]
        },
        {
            "destination": "/dev/pts",
            "type": "bind",
            "source": "/dev/pts",
            "options": [
                "rw",
                "rbind",
                "rshared"
            ]
        },
        {
            "destination": "/etc/resolv.conf",
            "type": "bind",
            "source": "/etc/resolv.conf",
            "options": [
                "rw",
                "rbind",
                "rshared"
            ]
        },
        {
            "destination": "/hostfs",
            "type": "bind",
            "source": "/",
            "options": [
                "rw",
                "rbind",
                "rshared"
            ]
        },
        {
            "destination": "/persist",
            "type": "bind",
            "source": "/var/persist",
            "options": [
                "rw",
                "rbind",
                "rshared"
            ]
        },
        {
            "destination": "/proc",
            "type": "proc",
            "source": "proc",
            "options": [
                "nosuid",
                "nodev",
                "noexec",
                "relatime"
            ]
        },
        {
            "destination": "/run",
            "type": "bind",
            "source": "/run",
            "options": [
                "rw",
                "rbind",
                "rshared"
            ]
        },
        {
            "destination": "/sys",
            "type": "sysfs",
            "source": "sysfs",
            "options": [
                "nosuid",
                "noexec",
                "nodev"
            ]
        },
        {
            "destination": "/sys/fs/cgroup",
            "type": "cgroup",
            "source": "cgroup",
            "options": [
                "nosuid",
                "noexec",
                "nodev",
                "relatime",
                "ro"
            ]
        }
    ],
    "linux": {
        "resources": {},
        "cgroupsPath": "/eve/services/xen-tools",
        "namespaces": [
            {
                "type": "mount"
            }
        ]
    }
}
`

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
	assert.Equal(t, []string{"eve", "exec", "pillar", "/opt/zededa/bin/veth.sh", "up", "test", "vif0", "br0", "52:54:00:12:34:56"}, s.Hooks.Prestart[0].Args)
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
	rootFsDir := path.Join(rootDir, "rootfs")
	podPath := path.Join(dir, imageConfigFilename)
	rsPath := path.Join(rootDir, ociRuntimeSpecFilename)
	err := os.MkdirAll(rootFsDir, 0777)
	if err != nil {
		t.Errorf("failed to create temporary dir")
	} else {
		defer os.RemoveAll(dir)
	}

	// now create a fake pod file...
	if err := ioutil.WriteFile(podPath, []byte(content), 0644); err != nil {
		t.Errorf("failed to write to a pod file %v", err)
	}
	// ...and a loader runtime spec
	if err := ioutil.WriteFile(rsPath, []byte(loaderRuntimeSpec), 0644); err != nil {
		t.Errorf("failed to write to a runtime spec file %v", err)
	}

	client := &Client{}
	spec, err := client.NewOciSpec("test")
	if err != nil {
		t.Errorf("failed to create new OCI spec %v", err)
	}
	if err := spec.UpdateFromVolume(dir); err != nil {
		t.Errorf("failed to load OCI image spec %v", err)
	}
	spec.UpdateMounts([]types.DiskStatus{
		{FileLocation: "/foo/baz.qcow2", Format: zconfig.Format_QCOW2},
		{FileLocation: "/foo/bar", Format: zconfig.Format_CONTAINER}})
	spec.Get().Root.Path = rootFsDir
	err = spec.AddLoader(rootDir)
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
	mountExpected := ""
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
	filename = filepath.Join(oldTempRootPath, "tmp", ociRuntimeSpecFilename)
	if err := ioutil.WriteFile(filename, []byte(loaderRuntimeSpec), 0644); err != nil {
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
			client := &Client{}
			spec, err := client.NewOciSpec("test")
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
			spec.Get().Root.Path = path.Join(oldTempRootPath, "rootfs")
			if err := spec.AddLoader(filepath.Join(oldTempRootPath, "tmp")); err != nil || tt.wantErr != nil {
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
				expectedMounts := ""
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

func TestUpdateMounts(t *testing.T) {
	g := NewGomegaWithT(t)
	spec := ociSpec{
		name:    "test",
		volumes: map[string]struct{}{"/myvol": {}, "/hisvol": {}},
		Spec: specs.Spec{
			Mounts: []specs.Mount{
				{Destination: "/test", Source: "/test", Type: "bind", Options: []string{"ro"}},
			},
			Annotations: map[string]string{},
		},
	}

	tresAmigos := []types.DiskStatus{
		{MountDir: "/", Format: zconfig.Format_CONTAINER, FileLocation: "/foo/bar"},
		{MountDir: "", Format: zconfig.Format_CONTAINER, FileLocation: "/foo/baz"},
		{MountDir: "/override", Format: zconfig.Format_QCOW2, FileLocation: "/foo/bam.qcow2", ReadOnly: true},
	}

	g.Expect(spec.UpdateMounts([]types.DiskStatus{})).ToNot(HaveOccurred())
	g.Expect(spec.UpdateMounts([]types.DiskStatus{{MountDir: "/", Format: zconfig.Format_CONTAINER}})).ToNot(HaveOccurred())

	g.Expect(spec.UpdateMounts(tresAmigos)).ToNot(HaveOccurred())
	g.Expect(spec.Mounts).To(ConsistOf([]specs.Mount{
		{Destination: "/test", Source: "/test", Type: "bind", Options: []string{"ro"}},
		{Destination: "/dev/eve/volumes/by-id/1", Type: "bind", Source: "/foo/baz/rootfs", Options: []string{"rbind", "rw"}},
		{Destination: "/dev/eve/volumes/by-id/2", Type: "bind", Source: "/foo/bam.qcow2", Options: []string{"rbind", "ro"}},
		{Destination: "/override/2", Type: "bind", Source: "/foo/bam.qcow2", Options: []string{"rbind", "ro"}},
	}))
	g.Expect(spec.Annotations).To(Equal(map[string]string{eveOCIMountPointsLabel: "/override\n"}))

	tresAmigos[1].MountDir = "foobar"
	g.Expect(spec.UpdateMounts(tresAmigos)).To(HaveOccurred())
}

func TestAddLoader(t *testing.T) {
	g := NewGomegaWithT(t)
	specTemplate := ociSpec{
		name:    "test",
		volumes: map[string]struct{}{"/myvol": {}, "/hisvol": {}},
		Spec: specs.Spec{
			Process: &specs.Process{
				Args: []string{"/bin/sh"},
				Cwd:  "/",
				Env:  []string{"FOO=foo", "BAR=bar"},
			},
			Root: &specs.Root{Path: "/"},
			Mounts: []specs.Mount{
				{Destination: "/test", Source: "/test", Type: "bind", Options: []string{"ro"}},
			},
			Annotations: map[string]string{},
			Linux:       &specs.Linux{CgroupsPath: "/foo/bar/baz"},
		},
	}
	spec1 := deepCopy(specTemplate).(ociSpec)
	spec2 := deepCopy(specTemplate).(ociSpec)

	tmpdir, err := ioutil.TempDir("/tmp", "volume")
	if err != nil {
		log.Fatalf("failed to create tmpdir %v", err)
	} else {
		defer os.RemoveAll(tmpdir)
	}
	if err := ioutil.WriteFile(filepath.Join(tmpdir, ociRuntimeSpecFilename), []byte(loaderRuntimeSpec), 0666); err != nil {
		log.Fatalf("failed to create tmpfile %v", err)
	}

	g.Expect(spec1.AddLoader("/foo/bar/baz")).To(HaveOccurred())

	g.Expect(spec1.AddLoader(tmpdir)).ToNot(HaveOccurred())
	g.Expect(spec1.Root).To(Equal(&specs.Root{Path: filepath.Join(tmpdir, "rootfs"), Readonly: true}))
	g.Expect(spec1.Linux.CgroupsPath).To(Equal("/foo/bar/baz"))
	g.Expect(spec1.Mounts[9]).To(Equal(specs.Mount{Destination: "/mnt/rootfs/test", Type: "bind", Source: "/test", Options: []string{"ro"}}))
	g.Expect(spec1.Mounts[0]).To(Equal(specs.Mount{Destination: "/dev", Type: "bind", Source: "/dev", Options: []string{"rw", "rbind", "rshared"}}))

	spec2.Root.Path = tmpdir
	g.Expect(spec2.AddLoader(tmpdir)).ToNot(HaveOccurred())
	g.Expect(spec2.Root).To(Equal(&specs.Root{Path: filepath.Join(tmpdir, "rootfs"), Readonly: true}))
	g.Expect(spec2.Linux.CgroupsPath).To(Equal("/foo/bar/baz"))
	g.Expect(spec2.Mounts[10]).To(Equal(specs.Mount{Destination: "/mnt/rootfs/test", Type: "bind", Source: "/test", Options: []string{"ro"}}))
	g.Expect(spec2.Mounts[9]).To(Equal(specs.Mount{Destination: "/mnt", Type: "bind", Source: path.Join(tmpdir, ".."), Options: []string{"rbind", "rw"}}))
	g.Expect(spec2.Mounts[0]).To(Equal(specs.Mount{Destination: "/dev", Type: "bind", Source: "/dev", Options: []string{"rw", "rbind", "rshared"}}))
}

func deepCopy(in interface{}) interface{} {
	b, _ := json.Marshal(in)
	p := reflect.New(reflect.TypeOf(in))
	output := p.Interface()
	_ = json.Unmarshal(b, output)
	val := reflect.ValueOf(output)
	val = val.Elem()
	return val.Interface()
}
