package registry

import (
	"time"
)

type Format int

const (
	FormatArtifacts Format = iota
	FormatLegacy
)

type LegacyOpt func(*legacyInfo)

type legacyInfo struct {
	timestamp *time.Time
	tmpdir    string
}

// WithTimestamp sets the timestamp to use for each file's tar header, else uses current time
func WithTimestamp(timestamp *time.Time) LegacyOpt {
	return func(info *legacyInfo) {
		info.timestamp = timestamp
	}
}

// WithTmpDir sets the temporary directory to use for tar/gzip the files. It is up to the caller to clean it up when done.
func WithTmpDir(dir string) LegacyOpt {
	return func(info *legacyInfo) {
		info.tmpdir = dir
	}
}
