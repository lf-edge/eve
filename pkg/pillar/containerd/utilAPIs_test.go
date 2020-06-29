package containerd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/satori/go.uuid"
)

const (
	oldTempBasePath = "/tmp/persist/pods/prepared"
	newTempBasePath = "/tmp/persist/vault/volumes"
)

var (
	containerID     = uuid.NewV4()
	containerDir    = fmt.Sprintf("%s#0.container", containerID.String())
	snapshotID      = containerDir
	oldTempRootPath = path.Join(oldTempBasePath, containerDir)
	newTempRootPath = path.Join(newTempBasePath, containerDir)
)

func TestGetContainerPath(t *testing.T) {
	type args struct {
		containerDir string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "TestGetContainerPath1",
			args: args{
				containerDir: "1a2b3c4d5e6f7g8h9i#0.container",
			},
			want: "/persist/runx/pods/prepared/1a2b3c4d5e6f7g8h9i#0.container",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetContainerPath(tt.args.containerDir); got != tt.want {
				t.Errorf("GetContainerPath() = %v, want %v", got, tt.want)
			}
		})
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

	err := os.MkdirAll(oldTempRootPath, 0777)
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
					"ENV2": "VAL2",
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
					"ENV2": "VAL2",
				},
				noOfDisks: 1,
			},
			wantErr: fmt.Errorf("createMountPointExecEnvFiles: Number of volumes provided: 0 is less than number of mount-points: 1. "),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := PrepareMount(tt.args.containerID, tt.args.containerPath, tt.args.envVars, tt.args.noOfDisks); err != nil || tt.wantErr != nil {
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
					"export ENV1=\"VAL1\"\n" +
					"export ENV2=\"VAL2\"\n"
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

func TestSaveSnapshotID(t *testing.T) {
	err := os.MkdirAll(newTempRootPath, 0777)
	if err != nil {
		t.Errorf("TestSaveSnapshotID: Failed to create %s: %s", newTempRootPath, err.Error())
	} else {
		defer os.RemoveAll(newTempRootPath)
	}

	type args struct {
		oldRootpath string
		newRootpath string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "TestSaveSnapshotID1",
			args: args{
				oldRootpath: oldTempRootPath,
				newRootpath: newTempRootPath,
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SaveSnapshotID(tt.args.oldRootpath, tt.args.newRootpath); err != nil || tt.wantErr != nil {
				if (tt.wantErr == nil) || ((err != nil) && (tt.wantErr.Error() != err.Error())) {
					t.Errorf("SaveSnapshotID() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				snapshotIDFile := path.Join(tt.args.newRootpath, snapshotIDFile)
				expectedSnapshotID := snapshotID
				snapshotID, err := ioutil.ReadFile(snapshotIDFile)
				if err != nil {
					t.Errorf("TestSaveSnapshotID: exception while reading %s file %s %v",
						snapshotIDFile, snapshotIDFile, err)
				}
				if string(snapshotID) != expectedSnapshotID {
					t.Errorf("TestSaveSnapshotID: mismatched %s file content, actual '%s' expected '%s'",
						snapshotIDFile, string(snapshotID), expectedSnapshotID)
				}
			}
		})
	}
}

func TestGetSnapshotID(t *testing.T) {
	err := os.MkdirAll(newTempRootPath, 0777)
	if err != nil {
		t.Errorf("TestPrepareMount: Failed to create %s: %s", oldTempRootPath, err.Error())
	} else {
		defer os.RemoveAll(newTempRootPath)
	}

	filename := filepath.Join(newTempRootPath, snapshotIDFile)
	if err := ioutil.WriteFile(filename, []byte(snapshotID), 0644); err != nil {
		t.Errorf("TestGetSnapshotID: exception while saving %s: %s", filename, err.Error())
	}
	type args struct {
		rootpath string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "TestGetSnapshotID1",
			args: args{
				rootpath: newTempRootPath,
			},
			want: snapshotID,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetSnapshotID(tt.args.rootpath); got != tt.want {
				t.Errorf("GetSnapshotID() = %v, want %v", got, tt.want)
			}
		})
	}
}
