// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

// TUIConfig carries TUI runtime configuration pushed from EVE.
type TUIConfig struct {
	LogLevel string `json:"logLevel"`
}

// LedBlinkCounter is the current LED blink-pattern code (see EVE's
// ledmanager); the TUI may surface it as a connectivity indicator.
type LedBlinkCounter struct {
	BlinkCounter uint32 `json:"blinkCounter"`
}
