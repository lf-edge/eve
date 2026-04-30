// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package netutils

import (
	"fmt"
	"os"
	"strings"
)

// IsLocalPortListening reports whether a process is bound and listening on
// port on localhost. It reads /proc/net/tcp[6] directly — no TCP connection
// is made, so a live virtctl VNC proxy on that port is not disturbed.
func IsLocalPortListening(port uint32) bool {
	hexPort := fmt.Sprintf("%04X", port)
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] { // skip header
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			// fields[1] = local_address "XXXXXXXX:PPPP", fields[3] = state ("0A" = LISTEN)
			parts := strings.SplitN(fields[1], ":", 2)
			if len(parts) == 2 && parts[1] == hexPort && fields[3] == "0A" {
				return true
			}
		}
	}
	return false
}
