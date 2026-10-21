//go:build !linux
// +build !linux

package can

import (
	"context"
)

func (i *Info) load(ctx context.Context) error {
	return nil
}
