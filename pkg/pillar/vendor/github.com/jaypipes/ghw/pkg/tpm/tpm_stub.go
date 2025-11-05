//go:build !linux
// +build !linux

package tpm

import (
	"github.com/jaypipes/ghw/pkg/option"
)

func (i *Info) load(opts *option.Options) error {
	return nil
}
