// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// CachedIP.String

func TestCachedIPString(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	c := CachedIP{IPAddress: ip, ValidUntil: ts}
	s := c.String()
	assert.Contains(t, s, "192.168.1.1")
}

// CachedResolvedIPs.String

func TestCachedResolvedIPsString(t *testing.T) {
	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	c := CachedResolvedIPs{
		Hostname: "example.com",
		CachedIPs: []CachedIP{
			{IPAddress: ip1, ValidUntil: ts},
			{IPAddress: ip2, ValidUntil: ts},
		},
	}
	s := c.String()
	assert.True(t, strings.HasPrefix(s, "Hostname example.com"))
	assert.Contains(t, s, "10.0.0.1")
	assert.Contains(t, s, "10.0.0.2")
}

func TestCachedResolvedIPsStringEmpty(t *testing.T) {
	c := CachedResolvedIPs{Hostname: "empty.com"}
	s := c.String()
	assert.Contains(t, s, "empty.com")
	assert.Contains(t, s, "[]")
}

// CachedResolvedIPs.Key / LogKey

func TestCachedResolvedIPsLogKey(t *testing.T) {
	c := CachedResolvedIPs{Hostname: "example.com"}
	assert.Equal(t, "example.com", c.Key())
	assert.Contains(t, c.LogKey(), "example.com")
}

// CachedResolvedIPs LogCreate / LogModify / LogDelete

func TestCachedResolvedIPsLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	c := CachedResolvedIPs{Hostname: "test.example.com"}
	c.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	c.LogModify(log, c)
	c.LogDelete(log)
}
