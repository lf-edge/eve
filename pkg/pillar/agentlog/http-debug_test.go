// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package agentlog

import (
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	pcd "github.com/lf-edge/eve/pkg/pillar/containerd"
)

func runDebugContainer() {
	ctrd, err := pcd.NewContainerdClient(false)
	if err != nil {
		panic(err)
	}

	ctx, done := ctrd.CtrNewSystemServicesCtx()
	defer done()

	containers, err := ctrd.CtrListContainer(ctx)
	if err != nil {
		log.Fatalf("could not list containers: %+v", err)
	}

	for _, container := range containers {
		ctrInfo, err := container.Info(ctx)
		if err != nil {
			log.Printf("could not get container info: %+v", err)
			continue
		}
		log.Printf("id: %v name: %s", container.ID(), ctrInfo.Runtime.Name)

	}

	image, err := ctrd.CtrPull(ctx, "docker.io/lfedge/eve-debug:latest")
	if err != nil {
		log.Fatal(err)
	}

	var container containerd.Container
	container, err = ctrd.CtrLoadContainer(ctx, "debug")
	if err != nil {
		log.Printf("Loading container failed (%v), trying to create it", err)
		container, err = ctrd.CtrNewContainerWithPersist(ctx, "debug", image)
		if err != nil {
			log.Fatal(err)
		}
		task, err := container.NewTask(ctx, cio.LogFile("/tmp/debug.container"))
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("created task: %+v", task)
	}

	log.Printf("container: %+v", container)

}

/*
 * How to run:
 * start pillar container and enter it:
  make pkg/pillar && docker run -it -v $(pwd):$(pwd) --cap-add=SYS_PTRACE \
      --cap-add=SYS_ADMIN --privileged --security-opt seccomp=unconfined \
      -v/root/.cache/go-build:$(pwd)/go-cache -w$(pwd)/pkg/pillar/agentlog \
      -p 6543:6543 $(docker images -q eve-build-$USER) bash
 * Setup cgroup:
  mkdir -p /sys/fs/cgroup/init
  echo 1 > /sys/fs/cgroup/init/cgroup.procs
  echo +cpu > /sys/fs/cgroup/cgroup.subtree_control
 * (all three commands have to be run from PID 1 of the container)
 * Install containerd:
  apk update && apk add containerd
 *
 * Start containerd: containerd &
 * Run it: SKIP=0 go test -race -timeout=0 -v -run=TestListenDebug
 *
*/

func TestListenDebug(t *testing.T) {
	var err error

	if os.Getenv("SKIP") != "0" {
		t.Skip()
	}

	err = os.MkdirAll("/hostfs/etc/", 0755)
	if err != nil {
		panic(err)
	}
	err = os.MkdirAll("/persist/tmp/", 0755)
	if err != nil {
		panic(err)
	}
	linuxkitYmlFile, err := filepath.Abs("../../../images/rootfs.yml.in")
	if err != nil {
		panic(err)
	}
	err = os.Symlink(linuxkitYmlFile, "/hostfs/etc/linuxkit-eve-config.yml")
	if err != nil && !os.IsExist(err) {
		panic(err)
	}

	runDebugContainer()
	_, log := Init("http-debug")
	listenAddress = "0.0.0.0:6543"
	ListenDebug(log, "stacks-dump-file", "mem-dump-file")
}
