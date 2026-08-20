// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// refSanitizer mirrors `tr '/:' '__'` applied by the build when it
// names images inside the OCI layout (pkg/kube-images/Dockerfile).
var refSanitizer = strings.NewReplacer("/", "_", ":", "_")

// sanitizeRef converts a real registry ref to the sanitized OCI
// ref-name the build assigns in the layout.
func sanitizeRef(realRef string) string { return refSanitizer.Replace(realRef) }

// loadRefMap reads the shipped ref list and returns sanitized -> real.
// Lines are repo:tag@sha256:...; only the tag part is a name, since an
// image record carrying the digest suffix would match no pod spec.
// A missing catalog maps nothing rather than failing.
func loadRefMap(listPath string) (map[string]string, error) {
	f, err := os.Open(listPath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", listPath, err)
	}
	defer func() { _ = f.Close() }()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ref, _, _ := strings.Cut(line, "@")
		m[sanitizeRef(ref)] = ref
	}
	return m, sc.Err()
}
