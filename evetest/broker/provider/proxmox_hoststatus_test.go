// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/luthermonson/go-proxmox"
)

// fakeHostAPI serves the endpoints ProxmoxProvider.HostStatus reads, with
// responses trimmed from a PVE 9.1 node, whose status reports cpu 0 (the
// utilization is in /cluster/resources). nodeStatus overrides the node
// status.
type fakeHostAPI struct {
	nodeStatus string
}

func (f *fakeHostAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api2/json/nodes/pve/status":
		if f.nodeStatus != "" {
			_, _ = io.WriteString(w, f.nodeStatus)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"cpu":0,"loadavg":["7.79","8.67","8.76"],`+
			`"cpuinfo":{"cores":20,"cpus":40,"model":"Intel(R) Xeon(R) CPU E5-2660 v3"},`+
			`"memory":{"available":20046630912,"free":18615631872,"total":67414343680,"used":47367712768},`+
			`"swap":{"free":6409371648,"total":8589930496,"used":2180558848}}}`)
	case "/api2/json/cluster/resources":
		if r.URL.Query().Get("type") != "node" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"data":[{"id":"node/other","node":"other","type":"node","cpu":0.9},`+
			`{"id":"node/pve","node":"pve","type":"node","cpu":0.25}]}`)
	case "/api2/json/version":
		_, _ = io.WriteString(w, `{"data":{"release":"9.1","repoid":"42db4a6cf33dac83","version":"9.1.1"}}`)
	case "/api2/json/nodes/pve/qemu":
		_, _ = io.WriteString(w, `{"data":[`+
			`{"vmid":100,"name":"evetest-broker","status":"running","maxmem":8589934592},`+
			`{"vmid":105,"name":"ev-eve-1a2b3c4d-edge-dev","status":"running","maxmem":17179869184},`+
			`{"vmid":107,"name":"ev-eve-1a2b3c4d-edge-dev2","status":"stopped","maxmem":17179869184}]}`)
	case "/api2/json/nodes/pve/storage/local-lvm/status":
		_, _ = io.WriteString(w, `{"data":{"total":373553102848,"used":266903691984,"avail":106649410864}}`)
	case "/api2/json/nodes/pve/storage/local/status":
		_, _ = io.WriteString(w, `{"data":{"total":100861726720,"used":10916364288,"avail":84774625280}}`)
	default:
		http.NotFound(w, r)
	}
}

func newFakeHostProvider(t *testing.T, api *fakeHostAPI, conf ProxmoxProviderConf) *ProxmoxProvider {
	t.Helper()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	conf.Node = "pve"
	return &ProxmoxProvider{
		conf:   conf,
		client: proxmox.NewClient(srv.URL+"/api2/json", proxmox.WithHTTPClient(srv.Client())),
	}
}

func TestProxmoxHostStatus(t *testing.T) {
	p := newFakeHostProvider(t, &fakeHostAPI{},
		ProxmoxProviderConf{Storage: "local-lvm", ImportStorage: "local"})
	st, err := p.HostStatus(context.Background())
	if err != nil {
		t.Fatalf("HostStatus failed: %v", err)
	}
	if st.Name != "pve" || st.Description != "Proxmox VE 9.1.1" || st.Cpus != 40 ||
		st.GetCpuUsage() != 0.25 || !slices.Equal(st.LoadAverage, []float64{7.79, 8.67, 8.76}) {
		t.Errorf("unexpected host: %v", st)
	}
	if st.MemoryTotalBytes != 67414343680 || st.MemoryAvailableBytes != 20046630912 ||
		st.SwapTotalBytes != 8589930496 || st.SwapUsedBytes != 2180558848 {
		t.Errorf("unexpected memory: %v", st)
	}
	if st.Vms != 3 || st.VmsRunning != 2 || st.VmsRunningMemoryBytes != 24<<30 {
		t.Errorf("unexpected VMs: %v", st)
	}
	if len(st.Storages) != 2 ||
		st.Storages[0].Name != "local-lvm" || st.Storages[0].Usage != "VM disks" ||
		st.Storages[0].AvailableBytes != 106649410864 ||
		st.Storages[1].Name != "local" || st.Storages[1].Usage != "image uploads" ||
		st.Storages[1].TotalBytes != 100861726720 {
		t.Errorf("unexpected storages: %v", st.Storages)
	}
}

// TestProxmoxHostStatusBeforePVE9 covers a node status without
// memory.available, which PVE added in version 9.
func TestProxmoxHostStatusBeforePVE9(t *testing.T) {
	p := newFakeHostProvider(t, &fakeHostAPI{nodeStatus: `{"data":{"cpu":0,` +
		`"loadavg":["1.00","2.00","3.00"],"cpuinfo":{"cpus":8},` +
		`"memory":{"free":1000,"total":10000,"used":7000},"swap":{"total":0,"used":0}}}`},
		ProxmoxProviderConf{Storage: "local", ImportStorage: "local"})
	st, err := p.HostStatus(context.Background())
	if err != nil {
		t.Fatalf("HostStatus failed: %v", err)
	}
	if st.MemoryAvailableBytes != 3000 {
		t.Errorf("got available memory %d, want total - used = 3000", st.MemoryAvailableBytes)
	}
	if len(st.Storages) != 1 || st.Storages[0].Usage != "VM disks, image uploads" {
		t.Errorf("want one storage for both uses, got %v", st.Storages)
	}
}
