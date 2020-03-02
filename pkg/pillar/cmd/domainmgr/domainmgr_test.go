// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage Xen guest domains based on the subscribed collection of DomainConfig
// and publish the result in a collection of DomainStatus structs.
// We run a separate go routine for each domU to be able to boot and halt
// them concurrently and also pick up their state periodically.

package domainmgr

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

type appImageNameEntry struct {
	filename    string
	dir         string
	sha         string
	appUUID     string
	imageFormat string
}

func TestParseAppRwImageName(t *testing.T) {
	testMatrix := map[string]appImageNameEntry{
		"Test owercase SHA": {
			filename: "/persist/img/EFA50C64CAACF8D43F334A05F8048F39A27FEA26FC1D155F2543D38D13176C17-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			dir:      "/persist/img",
			sha:      "EFA50C64CAACF8D43F334A05F8048F39A27FEA26FC1D155F2543D38D13176C17",
			appUUID:  "dfde839b-61f8-4df9-a840-d49cc0940d5c",
		},
		"Test uppercase SHA": {
			filename: "/persist/img/01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			dir:      "/persist/img",
			sha:      "01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848",
			appUUID:  "dfde839b-61f8-4df9-a840-d49cc0940d5c",
		},
		"Test No Dir": {
			filename: "01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			// We get return values of ""
			dir:     "",
			sha:     "",
			appUUID: "",
		},
		"Test Invalid Hash": {
			filename: "/persist/img/01434c4dK-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			// We get return values of ""
			dir:     "",
			sha:     "",
			appUUID: "",
		},
		"Test Invalid UUID": {
			filename: "/persist/img/01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848.qcow2",
			// We get return values of ""
			dir:     "",
			sha:     "",
			appUUID: "",
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		dir, sha, uuid := parseAppRwImageName(test.filename)
		if dir != test.dir {
			t.Errorf("dir ( %s ) != Expected value ( %s )", dir, test.dir)
		}
		if sha != test.sha {
			t.Errorf("sha ( %s ) != Expected value ( %s )", sha, test.sha)
		}
		if uuid != test.appUUID {
			t.Errorf("uuid ( %s ) != Expected value ( %s )", uuid, test.appUUID)
		}
	}
}

func TestFetchEnvVariablesFromCloudInit(t *testing.T) {
	type fetchEnvVar struct {
		config       types.DomainConfig
		expectOutput map[string]string
	}
	// testStrings are base 64 encoded strings which will contain
	// environment variables which user will pass in custom config
	// template in the manifest.
	// testString1 contains FOO=BAR environment variables which will
	// be set inside container.
	testString1 := "Rk9PPUJBUg=="
	// testString2 contains SQL_ROOT_PASSWORD=$omeR&NdomPa$$word environment variables which will
	// be set inside container.
	testString2 := "U1FMX1JPT1RfUEFTU1dPUkQ9JG9tZVImTmRvbVBhJCR3b3Jk"
	// testString3 contains PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
	// environment variables which wil be set inside container.
	testString3 := "UEFUSD0vdXNyL2xvY2FsL3NiaW46L3Vzci9sb2NhbC9iaW46L3Vzci9zYmluOi91c3IvYmluOi9zYmluOi9iaW4="
	// testString4 contains FOO=1 2 (with space in between)
	// environment variables which wil be set inside container.
	testString4 := "Rk9PPTEgMg=="
	// testString5 contains
	// FOO1=BAR1
	// FOO2=		[Without value]
	// FOO3			[Only key without delimiter]
	// FOO4=BAR4
	// environment variables which wil be set inside container.
	testString5 := "Rk9PMT1CQVIxCkZPTzI9CkZPTzMKRk9PND1CQVI0"
	testFetchEnvVar := map[string]fetchEnvVar{
		"Test env var 1": {
			config: types.DomainConfig{
				CloudInitUserData: &testString1,
			},
			expectOutput: map[string]string{
				"FOO": "BAR",
			},
		},
		"Test env var 2": {
			config: types.DomainConfig{
				CloudInitUserData: &testString2,
			},
			expectOutput: map[string]string{
				"SQL_ROOT_PASSWORD": "$omeR&NdomPa$$word",
			},
		},
		"Test env var 3": {
			config: types.DomainConfig{
				CloudInitUserData: &testString3,
			},
			expectOutput: map[string]string{
				"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			},
		},
		"Test env var 4": {
			config: types.DomainConfig{
				CloudInitUserData: &testString4,
			},
			expectOutput: map[string]string{
				"FOO": "1 2",
			},
		},
		"Negative test env var 5": {
			config: types.DomainConfig{
				CloudInitUserData: &testString5,
			},
		},
	}
	for testname, test := range testFetchEnvVar {
		t.Logf("Running test case %s", testname)
		envMap, err := fetchEnvVariablesFromCloudInit(test.config)
		switch testname {
		case "Negative test env var 5":
			if err == nil {
				t.Errorf("Fetching env variable from cloud init passed, expecting it to be failed.")
			}
		default:
			if err != nil {
				t.Errorf("Fetching env variable from cloud init failed: %v", err)
			}
			if !reflect.DeepEqual(envMap, test.expectOutput) {
				t.Errorf("Env map ( %v ) != Expected value ( %v )", envMap, test.expectOutput)
			}
		}
	}
}

func TestCreateMountPointExecEnvFiles(t *testing.T) {
	content := `
{
  "acVersion": "1.26.0",
  "acKind": "PodManifest",
  "apps": [
    {
      "name": "foobarbaz",
      "image": {
        "name": "registry-1.docker.io/library/redis",
        "id": "sha512-572dff895cc8521bcc800c7fa5224a121d3afa8b545ff9fd9c87d9c5ff090469",
        "labels": [
          {
            "name": "os",
            "value": "linux"
          },
          {
            "name": "arch",
            "value": "amd64"
          },
          {
            "name": "version",
            "value": "latest"
          }
        ]
      },
      "app": {
        "exec": [
          "docker-entrypoint.sh",
          "redis-server"
        ],
        "user": "0",
        "group": "0",
        "workingDirectory": "/data",
        "environment": [
          {
            "name": "PATH",
            "value": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
          },
          {
            "name": "GOSU_VERSION",
            "value": "1.11"
          },
          {
            "name": "REDIS_VERSION",
            "value": "5.0.7"
          },
          {
            "name": "REDIS_DOWNLOAD_URL",
            "value": "http://download.redis.io/releases/redis-5.0.7.tar.gz"
          },
          {
            "name": "REDIS_DOWNLOAD_SHA",
            "value": "61db74eabf6801f057fd24b590232f2f337d422280fd19486eca03be87d3a82b"
          }
        ],
        "mountPoints": [
          {
            "name": "volume-data",
            "path": "/data"
          },
					{
            "name": "foo",
            "path": "/foo"
          },
					{
            "name": "bar",
            "path": "/bar"
          }
        ],
        "ports": [
          {
            "name": "6379-tcp",
            "protocol": "tcp",
            "port": 6379,
            "count": 1,
            "socketActivated": false
          }
        ]
      }
    }
  ],
  "volumes": null,
  "isolators": null,
  "annotations": [
    {
      "name": "coreos.com/rkt/stage1/mutable",
      "value": "false"
    }
  ],
  "ports": []
}
`
	// create a temp dir to hold resulting files
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

	status := types.DomainStatus{DiskStatusList: []types.DiskStatus{{ImageSha256: "rootfs"}, {ImageSha256: "extraDiskData"}, {ImageSha256: "extraDiskFoo"}, {ImageSha256: "extraDiskBar"}}}
	execpath := []string{"docker-entrypoint.sh", "redis-server"}
	// the proper format for this
	execpathStr := "\"docker-entrypoint.sh\" \"redis-server\""
	workdir := "/data"
	mountpoints := []string{"/data", "/foo", "/bar"}
	env := []KeyValue{
		{Name: "PATH", Value: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		{Name: "GOSU_VERSION", Value: "1.11"},
		{Name: "REDIS_VERSION", Value: "5.0.7"},
		{Name: "REDIS_DOWNLOAD_URL", Value: "http://download.redis.io/releases/redis-5.0.7.tar.gz"},
		{Name: "REDIS_DOWNLOAD_SHA", Value: "61db74eabf6801f057fd24b590232f2f337d422280fd19486eca03be87d3a82b"},
	}

	err = createMountPointExecEnvFiles(rootDir, mountpoints, execpath, workdir, env, &status)
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
	mountExpected := strings.Join(mountpoints, "\n") + "\n"
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
	envExpect := fmt.Sprintf("export WORKDIR=\"%s\"\n", workdir)
	for _, v := range env {
		envExpect = envExpect + fmt.Sprintf("export %s=\"%s\"\n", v.Name, v.Value)
	}
	if err != nil {
		t.Errorf("createMountPointExecEnvFiles failed to create environment file %s %v", envFile, err)
	}
	if string(envActual) != envExpect {
		t.Errorf("mismatched env file content, actual '%s' expected '%s'", string(envActual), envExpect)
	}
}
