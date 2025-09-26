// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package netutils

import (
	"fmt"
	"net/url"
	"strings"
)

// BuildURLWithScheme returns a *url.URL with the given scheme applied.
// The scheme is always set to the provided value, overwriting any existing one.
func BuildURLWithScheme(address, scheme string) (*url.URL, error) {
	if address == "" {
		return nil, fmt.Errorf("address cannot be empty")
	}

	toParse := address
	if !strings.Contains(address, "://") {
		// Prepend scheme so url.Parse correctly sets URL.Host
		toParse = scheme + "://" + address
	}

	u, err := url.Parse(toParse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse address: %w", err)
	}

	// always enforce the required scheme
	u.Scheme = scheme

	return u, nil
}
