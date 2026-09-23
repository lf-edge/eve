// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// TestValidateExecArg is a regression test for argument injection (CWE-88):
// an attacker-controlled operand passed to an external command must not be
// allowed to act as an option (a leading '-'). This is the guard applied to the
// tcpdump filter and the traceroute target/timeout.
func TestValidateExecArg(t *testing.T) {
	// Must be rejected: these would be parsed as options by getopt.
	for _, bad := range []string{
		"-w/hostfs/tmp/pwn", // tcpdump -w file write (the reported injection)
		"-i",                // traceroute -i interface
		"-sKILL",            // timeout -s signal
		"--",                // end-of-options marker
		"  -w/x",            // leading spaces then a dash
		"\t-x",              // leading tab then a dash
		"\n-w/x",            // leading newline then a dash
	} {
		if err := validateExecArg("arg", bad); err == nil {
			t.Errorf("expected input %q to be rejected", bad)
		}
	}

	// Must pass: legitimate operands (filters, hosts, timeouts) never lead with
	// '-', and embedded dashes are harmless in a single argv token.
	for _, ok := range []string{
		"port 80", "host 1.2.3.4", "tcp", "8.8.8.8", "1.2.3.4",
		"example.com", "a-b-c", "1.2.3.4:80", "60", "",
		"60; rm", // non-option junk is harmless: no shell, one argv token
	} {
		if err := validateExecArg("arg", ok); err != nil {
			t.Errorf("expected input %q to be accepted: %v", ok, err)
		}
	}
}
