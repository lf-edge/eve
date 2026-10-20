// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import "testing"

func TestCPUTopology(t *testing.T) {
	tests := []struct {
		name                            string
		cpus, threadsPerCore            uint
		wantSockets, wantCores, wantThr uint
	}{
		// The default must reproduce exactly what the providers did before
		// threads-per-core existed: every CPU its own single-thread core.
		{"unset is one thread per core", 8, 0, 1, 8, 1},
		{"explicit 1 is one thread per core", 8, 1, 1, 8, 1},

		{"SMT halves the core count", 8, 2, 1, 4, 2},
		{"SMT with the minimum core count", 2, 2, 1, 1, 2},

		// A partial core cannot be presented to a guest, so an indivisible
		// request degrades to the default rather than being rounded.
		{"odd CPU count cannot be SMT", 7, 2, 1, 7, 1},
		{"four threads per core", 8, 4, 1, 2, 4},
		{"threads exceeding CPUs degrade", 2, 4, 1, 2, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sockets, cores, threads := CPUTopology(tt.cpus, tt.threadsPerCore)
			if sockets != tt.wantSockets || cores != tt.wantCores || threads != tt.wantThr {
				t.Errorf("CPUTopology(%d, %d) = %d/%d/%d, want %d/%d/%d",
					tt.cpus, tt.threadsPerCore, sockets, cores, threads,
					tt.wantSockets, tt.wantCores, tt.wantThr)
			}
			// However the CPUs are arranged, the guest must still end up with
			// the number of logical CPUs it asked for.
			if got := sockets * cores * threads; got != tt.cpus {
				t.Errorf("topology describes %d logical CPUs, want %d", got, tt.cpus)
			}
		})
	}
}

func TestSMPArg(t *testing.T) {
	if got, want := smpArg(8, 0), "8,sockets=1,cores=8,threads=1"; got != want {
		t.Errorf("smpArg(8, 0) = %q, want %q", got, want)
	}
	if got, want := smpArg(8, 2), "8,sockets=1,cores=4,threads=2"; got != want {
		t.Errorf("smpArg(8, 2) = %q, want %q", got, want)
	}
}
