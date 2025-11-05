//go:build !linux
// +build !linux

// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package serial

import (
	"fmt"
	"runtime"

	"github.com/zededa/ghw/pkg/option"
)

func (i *Info) load(opts *option.Options) error {
	return fmt.Errorf("serial load not implemented on %s", runtime.GOOS)
}
