// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage Xen guest domains based on the subscribed collection of DomainConfig
// and publish the result in a collection of DomainStatus structs.
// We run a separate go routine for each domU to be able to boot and halt
// them concurrently and also pick up their state periodically.

package domainmgr

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

type podManifestEntry struct {
	content     string
	podManifest RktPodManifest
}

func TestParsePodManifest(t *testing.T) {
	testMatrix := map[string]podManifestEntry{
		"Test redis app manifest": {
			content: `
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
`,
			podManifest: RktPodManifest{
				ACVersion: "1.26.0",
				ACKind:    "PodManifest",
				Apps: []RktApp{{
					Name: "foobarbaz",
					App: RktAppInstance{
						Exec:    []string{"docker-entrypoint.sh", "redis-server"},
						User:    "0",
						Group:   "0",
						WorkDir: "/data",
						Env: []KeyValue{
							{Name: "PATH", Value: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
							{Name: "GOSU_VERSION", Value: "1.11"},
							{Name: "REDIS_VERSION", Value: "5.0.7"},
							{Name: "REDIS_DOWNLOAD_URL", Value: "http://download.redis.io/releases/redis-5.0.7.tar.gz"},
							{Name: "REDIS_DOWNLOAD_SHA", Value: "61db74eabf6801f057fd24b590232f2f337d422280fd19486eca03be87d3a82b"},
						},
						Mounts: []MountPoint{
							{Name: "volume-data", Path: "/data"},
						},
					},
				},
				},
			},
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		file, err := ioutil.TempFile("/tmp", "podmanifest")
		if err != nil {
			t.Errorf("failed to create temporary file")
		} else {
			defer os.Remove(file.Name())
		}

		_, err = file.WriteString(test.content)
		if err != nil {
			t.Errorf("failed to write to temporary file")
		}

		podManifest, err := getRktPodManifest(file.Name())
		if err != nil {
			t.Errorf("failed to parse Rkt Manifest")
		}

		if !reflect.DeepEqual(podManifest, test.podManifest) {
			res, _ := json.Marshal(podManifest)
			fmt.Println(string(res))
			t.Errorf("podManifests don't match")
		}
	}
}
