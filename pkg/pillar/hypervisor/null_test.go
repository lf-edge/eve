// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

var hyper Hypervisor

func init() {
	var err error
	hyper, err = GetHypervisor("null")
	if hyper.Name() != "null" || err != nil {
		panic(fmt.Sprintf("Requested null hypervisor, got %s (with error %v) instead", hyper.Name(), err))
	}
}

func TestNullCreate(t *testing.T) {
	if _, err := hyper.Create("", "", 0); err == nil {
		t.Errorf("Create domain should've failed for empty arguments")
	}

	if _, err := hyper.Create("", "/foo-bar-baz", 0); err == nil {
		t.Errorf("Create domain should've failed for non-existen config")
	}
}

func TestPCIAssignments(t *testing.T) {
	if err := hyper.PCIRelease("00:1f.0"); err == nil {
		t.Errorf("PCIRelease should've failed for a PCI endpoint that isn't reserved")
	}

	if err := hyper.PCIReserve("00:1f.0"); err != nil {
		t.Errorf("PCIReserve failed %v", err)
	}

	if err := hyper.PCIReserve("00:1f.0"); err == nil {
		t.Errorf("PCIReserve should've failed for a PCI endpoint that is already reserved")
	}

	if err := hyper.PCIRelease("00:1f.0"); err != nil {
		t.Errorf("PCIRelease failed %v", err)
	}
}

func TestBasicNullDomainWorkflow(t *testing.T) {
	// t.Logf("Running test case")
	conf, err := ioutil.TempFile("", "config")
	if err != nil {
		t.Errorf("Can't create config file for a domain %v", err)
	} else {
		defer os.Remove(conf.Name())
	}
	if _, err := conf.WriteString(`name = "test.1"
type = "pv"
uuid = "9330ccad-9b9d-4a9d-8059-ba03c70376f5"
kernel = "/persist/downloads/appImg.obj/verified/604A43D23373715D0F7C26F4107698A9FB60AAE7067470B0CB60870A2F6AF174/mirage"
vnc = 0
memory = 250
maxmem = 250
vcpus = 1
maxcpus = 1
root = "/dev/xvda1"
extra = "console=hvc0 appuuid=9330ccad-9b9d-4a9d-8059-ba03c70376f5 "
boot = "dc"
disk = []
vif = []
serial = ['pty']
`); err != nil {
		t.Errorf("Can't write config file for a domain %v", err)
	} else {
		conf.Close()
	}

	domID, err := hyper.Create("test.1", conf.Name(), 0)
	if err != nil {
		t.Errorf("Create domain test failed %v", err)
	}

	ctx := hyper.(nullContext)
	if _, err := os.Stat(ctx.tempDir + "/test.1"); err != nil {
		t.Errorf("Create domain didn't deposit a file %s %v", ctx.tempDir, err)
	}

	if err := hyper.Stop("test.1", domID, true); err == nil {
		t.Errorf("Stop domain should've failed for a domain that is not running")
	}

	if err := hyper.Start("test.1", domID); err != nil {
		t.Errorf("Couldn't start a domain %v", err)
	}

	if err := hyper.Start("test.1", domID); err == nil {
		t.Errorf("Start domain should've failed for a domain that is already running")
	}

	if err := hyper.Stop("test.1", domID, false); err != nil {
		t.Errorf("Couldn't stop a domain %v", err)
	}

	if id, err := hyper.LookupByName("test.1", domID); err != nil || id != domID {
		t.Errorf("LookupByName domain failed %d %v", id, err)
	}

	if err := hyper.Info("", 0); err == nil {
		t.Errorf("Info domain should've failed for a domain that is empty")
	}

	if err := hyper.Info("foo-bar-baz", 0); err == nil {
		t.Errorf("Info domain should've failed for a domain that is non-existent")
	}

	if err := hyper.Info("test.1", domID); err != nil {
		t.Errorf("Info domain failed %v", err)
	}

	if err := hyper.Delete("test.1", domID); err != nil {
		t.Errorf("Delete domain failed %v", err)
	}
}
