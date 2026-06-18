package partitionresizer

import (
	"fmt"
	"io"
	"os"
)

const (
	// 4 MiB is a good default; bump to 8–16 MiB on NVMe
	copyBufSize = 4 * 1024 * 1024
)

// CopyRange copies `length` bytes starting at `srcOffset` in srcPath
// into dstPath starting at `dstOffset`.
// If dstOffset < 0, dst is truncated and written from offset 0.
func CopyRange(srcPath, dstPath string, srcOffset, dstOffset, length int64, bufsize int) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open src: %w", err)
	}
	defer func() { _ = src.Close() }()

	dstFlags := os.O_CREATE | os.O_RDWR

	dst, err := os.OpenFile(dstPath, dstFlags, 0644)
	if err != nil {
		return fmt.Errorf("open dst: %w", err)
	}
	defer func() { _ = dst.Close() }()

	if dstOffset < 0 {
		if err := dst.Truncate(0); err != nil {
			return fmt.Errorf("truncate dst: %w", err)
		}
		dstOffset = 0
	}

	if bufsize <= 0 {
		bufsize = copyBufSize
	}
	buf := make([]byte, bufsize)
	var copied int64

	for copied < length {
		toRead := int64(len(buf))
		if remaining := length - copied; remaining < toRead {
			toRead = remaining
		}

		n, err := src.ReadAt(buf[:toRead], srcOffset+copied)
		if err != nil && err != io.EOF {
			return fmt.Errorf("read: %w", err)
		}
		if n == 0 {
			break
		}

		wn, werr := dst.WriteAt(buf[:n], dstOffset+copied)
		if werr != nil {
			return fmt.Errorf("write: %w", werr)
		}
		if wn != n {
			return fmt.Errorf("short write: %d != %d", wn, n)
		}

		copied += int64(n)
	}

	return dst.Sync()
}
