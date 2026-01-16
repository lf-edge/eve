package tpm

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zededa/ghw/pkg/linuxpath"
	"github.com/zededa/ghw/pkg/option"
	"github.com/zededa/ghw/pkg/util"
)

func (i *Info) load(opts *option.Options) error {
	paths := linuxpath.New(opts)
	// Check /sys/class/tpm/tpm0
	tpmPath := filepath.Join(paths.SysClassTpm, "tpm0")
	if _, err := os.Stat(tpmPath); err != nil {
		i.Present = false
		return nil
	}
	i.Present = true

	// Try to read 'caps' file which often contains info
	capsPath := filepath.Join(tpmPath, "caps")
	if file, err := os.Open(capsPath); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			switch key {
			case "Manufacturer":
				i.Manufacturer = val
			case "TCG version":
				i.SpecVersion = val
			case "Firmware version":
				i.FirmwareVersion = val
			}
		}
	}

	// Fallback/Override from device/ links if caps didn't provide it
	if i.Manufacturer == "" {
		// Try device/vendor (PCI)
		if b, err := os.ReadFile(filepath.Join(tpmPath, "device", "vendor")); err == nil {
			i.Manufacturer = strings.TrimSpace(string(b))
		}
	}

	// Fallback for SpecVersion using tpm_version_major
	if i.SpecVersion == "" {
		versionMajor := util.SafeIntFromFile(opts, filepath.Join(tpmPath, "tpm_version_major"))
		if versionMajor > 0 {
			i.SpecVersion = strconv.Itoa(versionMajor) + ".0"
		}
	}

	return nil
}
