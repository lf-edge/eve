// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"testing"

	"github.com/lf-edge/eve-libs/zedUpload"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestTransportHandlersDefaultMatchesLibrary pins the default of
// downloader.transport.handlers to the zedUpload transport's own default: a
// device that never sets the knob must get the transport it always had.
func TestTransportHandlersDefaultMatchesLibrary(t *testing.T) {
	handlers := types.DefaultConfigItemValueMap().GlobalValueInt(
		types.DownloaderTransportHandlers)
	if int(handlers) != zedUpload.DefaultNumberOfHandlers {
		t.Fatalf("default is %d handlers, the transport's own default is %d",
			handlers, zedUpload.DefaultNumberOfHandlers)
	}
}
