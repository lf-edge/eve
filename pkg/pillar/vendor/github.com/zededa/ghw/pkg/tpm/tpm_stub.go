//go:build !linux
// +build !linux

package tpm

import (
	"github.com/zededa/ghw/pkg/option"
)

func (i *Info) load(opts *option.Options) error {
	return nil
}
