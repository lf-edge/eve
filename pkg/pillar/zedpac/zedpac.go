// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedpac

import (
	"fmt"

	"github.com/jackwakefield/gopac"
)

func Find_proxy_sync(pac, url, host string) (string, error) {
	parser := new(gopac.Parser)
	if err := parser.ParseBytes([]byte(pac)); err != nil {
		return "", fmt.Errorf("invalid proxy auto-configuration file: %v", err)
	}

	return parser.FindProxy(url, host)
}
