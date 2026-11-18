// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	pb "github.com/lf-edge/eve/evetest/grpcapi/go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPrintBrokerStatus(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) *timestamppb.Timestamp { return timestamppb.New(now.Add(-d)) }
	resp := &pb.GetStatusResponse{
		BrokerVersion: "40845c9b62685e7b",
		Provider:      "proxmox",
		StartedAt:     ago(2 * time.Hour),
		MaxClients:    -1,
		Sessions: []*pb.ClientSessionStatus{
			{
				ClientId:    "23e73b08",
				PeerAddress: "10.208.13.70:51234",
				ClientInfo: &pb.ClientInfo{
					Hostname: "runner-2",
					CiRunUrl: "https://github.com/lf-edge/eve/actions/runs/1/attempts/1",
					CiJob:    "run-suite",
					CiRunner: "runner-2",
				},
				ConnectedAt:        ago(time.Hour),
				LastKeepAlive:      ago(4 * time.Second),
				CurrentTest:        "TestNodeClusterSuite/TestFailover",
				Operation:          "SetupDevices",
				OperationStartedAt: ago(90 * time.Second),
				Devices: []*pb.DeviceStatus{
					{Name: "sdn", IsSdn: true, VmName: "sdn-23e73b08", Created: true,
						Arch: pb.ArchType_ARCH_AMD64, Cpus: 2, MemoryBytes: 1 << 30,
						Image: "lfedge/evetest-sdn:abc"},
					{Name: "edge-dev1", VmName: "eve-23e73b08-edge-dev1",
						Arch: pb.ArchType_ARCH_AMD64, Image: "lfedge/eve:14.5.0-kvm-amd64"},
				},
			},
			{ClientId: "aaaa0000", ConnectedAt: ago(time.Minute)},
		},
		ImageUploads: []*pb.ImageUploadStatus{
			{Image: "evebuild/pr:7145-kvm-amd64", ClaimedAt: ago(10 * time.Minute),
				PeerAddress: "10.208.13.71:40000",
				ClientInfo: &pb.ClientInfo{
					Hostname: "runner-3",
					CiRunUrl: "https://github.com/lf-edge/eve/actions/runs/2/attempts/1",
					CiJob:    "stage-image",
					CiRunner: "runner-3",
				},
				UploadStartedAt: ago(2 * time.Minute), LoadedBytes: 512 << 20, ArchiveSizeBytes: 2048 << 20,
				ExpiresAt: timestamppb.New(now.Add(10 * time.Minute))},
			{Image: "evebuild/pr:7145-k-amd64", ClaimedAt: ago(5 * time.Minute),
				ExpiresAt: timestamppb.New(now.Add(55 * time.Minute))},
		},
		Host: &pb.HostStatus{
			Name:                  "pve",
			Description:           "Proxmox VE 9.1.1",
			Cpus:                  40,
			CpuUsage:              proto.Float64(0.25),
			LoadAverage:           []float64{7.79, 8.67, 8.76},
			MemoryTotalBytes:      64 << 30,
			MemoryAvailableBytes:  16 << 30,
			SwapTotalBytes:        8 << 30,
			SwapUsedBytes:         2 << 30,
			Vms:                   14,
			VmsRunning:            11,
			VmsRunningMemoryBytes: 80 << 30,
			Storages: []*pb.StorageStatus{
				{Name: "local-lvm", Usage: "VM disks", TotalBytes: 348 << 30, AvailableBytes: 99 << 30},
				{Name: "local", Usage: "image uploads", TotalBytes: 94 << 30, AvailableBytes: 79 << 30},
			},
		},
	}
	var out bytes.Buffer
	printBrokerStatus(&out, resp, now)
	got := out.String()
	for _, want := range []string{
		"Broker 40845c9b62685e7b (proxmox provider), up 2h0m0s, 2 client session(s) (max unlimited)\n",
		"\nHost pve (Proxmox VE 9.1.1)\n" +
			"  CPU:       40 CPUs, 25% used, load 7.79 8.67 8.76\n" +
			"  Memory:    16.0 GiB of 64.0 GiB available, swap 2.0 GiB of 8.0 GiB used\n" +
			"  VMs:       11 running of 14, 80.0 GiB assigned to running VMs (125% of host memory)\n" +
			"  Storage:   local-lvm (VM disks): 99.0 GiB of 348.0 GiB available\n" +
			"             local (image uploads): 79.0 GiB of 94.0 GiB available\n",
		"\nImage upload evebuild/pr:7145-kvm-amd64 from 10.208.13.71:40000\n" +
			"  Host:      runner-3\n" +
			"  CI:        https://github.com/lf-edge/eve/actions/runs/2/attempts/1 (job stage-image, runner runner-3)\n" +
			"  State:     uploading for 2m0s, 25% (512.0 MiB of 2048.0 MiB) loaded\n" +
			"  Claimed:   10m0s ago, lapses in 10m0s\n",
		"\nImage upload evebuild/pr:7145-k-amd64\n" +
			"  State:     fetching the image, upload not started\n" +
			"  Claimed:   5m0s ago, lapses in 55m0s\n",
		"\nClient 23e73b08 from 10.208.13.70:51234\n",
		"  Host:      runner-2\n",
		"  CI:        https://github.com/lf-edge/eve/actions/runs/1/attempts/1 (job run-suite, runner runner-2)\n",
		"  Connected: 1h0m0s ago, last keep-alive 4s ago\n",
		"  Test:      TestNodeClusterSuite/TestFailover\n",
		"  Operation: SetupDevices (for 1m30s)\n",
		"    sdn        sdn-23e73b08            yes      amd64  2     1.0GiB  lfedge/evetest-sdn:abc\n",
		"    edge-dev1  eve-23e73b08-edge-dev1  no       amd64  -     -       lfedge/eve:14.5.0-kvm-amd64\n",
		"\nClient aaaa0000\n  Connected: 1m0s ago\n  Devices:   none\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
}

func TestPrintBrokerStatusHostError(t *testing.T) {
	var out bytes.Buffer
	printBrokerStatus(&out, &pb.GetStatusResponse{
		BrokerVersion: "v", Provider: "proxmox", MaxClients: 2,
		HostError: "failed to get status of node pve: 401 Unauthorized",
	}, time.Now())
	want := "\nHost: unavailable: failed to get status of node pve: 401 Unauthorized\n"
	if !strings.Contains(out.String(), want) {
		t.Errorf("output lacks %q:\n%s", want, out.String())
	}
}
