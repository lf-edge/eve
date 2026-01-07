package watchdog

import (
	"os"
	"path/filepath"

	"github.com/jaypipes/ghw/pkg/option"
)

func (i *Info) load(opts *option.Options) error {
	// Check /dev/watchdog
	// In chroot? /dev might be bind mounted or not. But `linuxpath` usually handles /sys /proc etc.
	// But let's assume `dev` is relative to root if we are checking device existence.
	if _, err := os.Stat(filepath.Join(opts.Chroot, "dev", "watchdog")); err == nil {
		i.Present = true
		return nil
	}

	// Check /sys/class/watchdog/
	entries, err := os.ReadDir(filepath.Join(opts.Chroot, "sys", "class", "watchdog"))
	if err == nil && len(entries) > 0 {
		i.Present = true
	}

	return nil
}
