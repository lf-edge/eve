// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cloudconfig

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// Not os.Root: it refuses an absolute symlink outright ("Symbolic links must
// not be absolute"), so /var/run -> /run would fail rather than resolve to the
// application's own /run. It is the right tool only if refusing such a path
// ever becomes the wanted behaviour.

// maxSymlinkDepth caps how many symlinks-to-missing-directories ensureDirPath
// will follow. Serves the same purpose as the kernel's ELOOP limit, on the one
// case the kernel cannot resolve for us: a directory that has to be created
// through a symlink whose target does not exist yet.
const maxSymlinkDepth = 8

// maxResolveRetries bounds the retries of a lookup the kernel declined to
// answer. It expects a retry to succeed promptly, so a tree being mutated hard
// enough to exhaust this fails rather than spinning.
const maxResolveRetries = 16

// tmpCounter distinguishes the temporary files of successive writes, so a
// leftover from an interrupted write cannot make the next one fail on O_EXCL.
var tmpCounter atomic.Uint64

// writeFileInRoot writes content at filePath with the given mode, resolving
// filePath as though rootPath were the filesystem root, and creates the parent
// directories that do not exist yet.
//
// filePath comes from a cloud-config write_files entry and is resolved against
// the rootfs of the application's own container image, so every symlink along
// the way is chosen by whoever built that image. openat2(2) with
// RESOLVE_IN_ROOT has the kernel resolve the path with rootPath as "/":
// absolute symlink targets are re-rooted at rootPath and ".." cannot climb
// above it. Those are chroot(2) semantics without chroot's process-wide
// effect, and unlike resolving the path in userspace there is no window
// between deciding a path is safe and writing to it.
//
// Re-rooting rather than rejecting is what the guest itself means by such a
// path: in a Debian-based image /var/lock is a symlink to /run/lock, and a
// write there belongs in the container's own /run/lock.
//
// Containment does not rest on this function being the only writer, nor on it
// never creating a symlink: every call re-resolves from its own root
// descriptor, so it tolerates whatever symlinks it finds. A container-format
// volume may in fact be shared writable with an already-running application
// (see checkReferences in volumemgr), so a concurrent writer must be assumed.
//
// It does rest on two properties of the caller's namespace:
//   - No directory is moved out of rootPath mid-write, since a descriptor
//     follows its directory. The mount boundary is what gives this: a guest
//     sees such a volume only as a bind mount of that tree, and rename(2)
//     cannot cross mounts. A rename within the root stays contained.
//   - No outside inode is exposed beneath rootPath by a mount pillar can see.
//     RESOLVE_IN_ROOT confines path resolution to the tree, not to one
//     filesystem, so an interior mount would be followed (RESOLVE_NO_XDEV
//     would forbid that, at the cost of any legitimate interior mount).
//
// Needs Linux 5.6 for openat2.
func writeFileInRoot(rootPath, filePath string, content []byte, mode os.FileMode) error {
	dir, name, err := normalizeInRoot(filePath)
	if err != nil {
		return err
	}

	rootFd, err := retryOnEINTR2(func() (int, error) {
		return unix.Open(rootPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	})
	if err != nil {
		return fmt.Errorf("failed to open root path %s: %w", rootPath, err)
	}
	defer unix.Close(rootFd)

	if err := ensureDirPath(rootFd, dir, 0); err != nil {
		return err
	}
	// Opened read-only rather than O_PATH so the directory can be fsynced
	// after the rename.
	dirFd, err := openInRoot(rootFd, dir, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return fmt.Errorf("failed to open directory %s under %s: %w", dir, rootPath, err)
	}
	defer unix.Close(dirFd)

	return writeRenameAt(dirFd, name, content, mode)
}

// normalizeInRoot splits a requested path into the directory to resolve and
// the name to write inside it, and rejects a path that climbs above the root.
//
// The split is not a containment measure -- RESOLVE_IN_ROOT already makes an
// escape impossible whatever this returns. It exists because rename(2) is what
// makes the write atomic, and renameat takes a directory descriptor plus a
// plain name, with no resolve-flag variant. path.Dir and path.Base alone would
// not do, as they disagree about a trailing separator: "/foo/" would name the
// file "foo" inside a directory "/foo".
//
// ".." is left in dir for the kernel to resolve. Collapsing it here would
// apply it before symlinks rather than after, naming a different directory:
// with "/alias" a symlink to "real/deep", "/alias/../f" is "/real/f", not
// "/f".
//
// The climb-out rejection is a lexical sanity check on the config, not a
// containment mechanism, and it is deliberately approximate in both
// directions: with "/a" a symlink to "/", "/a/../f" is accepted although the
// traversal does climb to the root, and with "/a" a symlink to "real/deep",
// "/a/../../f" is rejected although it resolves to a contained path. It earns
// its place only by turning a plainly malformed entry into an error instead of
// a file written somewhere its author did not name; the kernel is what keeps
// either outcome inside the root.
func normalizeInRoot(filePath string) (dir, name string, err error) {
	invalid := fmt.Errorf(
		"detected possible attempt to write file outside of root path. invalid path %s",
		filePath)

	var components []string
	for _, component := range strings.Split(filePath, "/") {
		// Dropping "." changes no meaning; ".." is kept for the kernel.
		if component != "" && component != "." {
			components = append(components, component)
		}
	}
	if len(components) == 0 {
		// Names the root directory itself, not a file in it.
		return "", "", invalid
	}
	if components[len(components)-1] == ".." {
		return "", "", invalid
	}
	// Whether the path climbs out, counted lexically. A symlink can make the
	// kernel disagree about which directory a ".." lands in, but not about
	// whether the path stays inside the root.
	depth := 0
	for _, component := range components {
		if component == ".." {
			if depth == 0 {
				return "", "", invalid
			}
			depth--
			continue
		}
		depth++
	}

	last := len(components) - 1
	return "/" + strings.Join(components[:last], "/"), components[last], nil
}

// openInRoot opens path with rootFd standing in for the filesystem root.
//
// A ".." under RESOLVE_IN_ROOT is only safe if the kernel can confirm it did
// not escape, which it cannot always do while the tree is changing underneath;
// it then reports EAGAIN and leaves retrying to the caller (openat2(2)). So
// EAGAIN here says nothing about the path -- treating it as a failure makes a
// perfectly good entry fail whenever something else touches the filesystem at
// the wrong moment.
func openInRoot(rootFd int, path string, flags int) (int, error) {
	var fd int
	var err error
	for attempt := 0; attempt <= maxResolveRetries; attempt++ {
		fd, err = retryOnEINTR2(func() (int, error) {
			return unix.Openat2(rootFd, path, &unix.OpenHow{
				Flags:   uint64(flags | unix.O_CLOEXEC),
				Resolve: unix.RESOLVE_IN_ROOT,
			})
		})
		if !errors.Is(err, unix.EAGAIN) {
			return fd, err
		}
	}
	return fd, err
}

// ensureDirPath creates every component of dir that does not exist yet, each
// one below a parent the kernel has already resolved inside the root.
//
// Prefixes are built by concatenation rather than by path.Join, because a
// symlink target may contain "..": cleaning it would name an ancestor of the
// link's own lexical path instead of an ancestor of what the link points at.
// Left intact, every prefix is resolved by the kernel, which follows the real
// symlinks before applying the "..".
func ensureDirPath(rootFd int, dir string, depth int) error {
	if depth > maxSymlinkDepth {
		return fmt.Errorf("too many symbolic links while creating %s", dir)
	}
	parent, full := "/", ""
	for _, name := range strings.Split(dir, "/") {
		if name == "" || name == "." {
			continue
		}
		if full != "" {
			parent = full
		}
		full += "/" + name
		// ".." always exists, and only the kernel can say what it refers to
		// once symlinks are in play.
		if name == ".." {
			continue
		}
		if err := ensureDir(rootFd, parent, full, name, depth); err != nil {
			return err
		}
	}
	return nil
}

// ensureDir makes sure name, whose full path within the root is full and whose
// parent is parent, exists as a directory. A name that is a symlink to a
// directory which does not exist yet is not created itself -- mkdir would fail
// on the symlink -- its target is created instead, which RESOLVE_IN_ROOT keeps
// inside the root.
func ensureDir(rootFd int, parent, full, name string, depth int) error {
	fd, err := openInRoot(rootFd, full, unix.O_PATH|unix.O_DIRECTORY)
	if err == nil {
		unix.Close(fd)
		return nil
	}
	// Anything but "not there" (ENOTDIR for a file in the way, ELOOP, EACCES)
	// is the useful error and must not be masked by the EEXIST below.
	if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("failed to open %s: %w", full, err)
	}

	parentFd, err := openInRoot(rootFd, parent, unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", parent, err)
	}
	defer unix.Close(parentFd)

	mkErr := retryOnEINTR(func() error { return unix.Mkdirat(parentFd, name, 0755) })
	if mkErr == nil {
		return nil
	}
	if !errors.Is(mkErr, unix.EEXIST) {
		return fmt.Errorf("failed to create %s: %w", full, mkErr)
	}

	// The name exists yet did not resolve to a directory: either a symlink
	// whose target is missing, whose target is created below, or a directory
	// that appeared between the lookup and the mkdir.
	target, err := readlinkAt(parentFd, name)
	if err != nil {
		if fd, openErr := openInRoot(rootFd, full, unix.O_PATH|unix.O_DIRECTORY); openErr == nil {
			unix.Close(fd)
			return nil
		}
		return fmt.Errorf("failed to create %s: exists but is not a usable directory: %w",
			full, err)
	}
	if !path.IsAbs(target) {
		// Concatenated rather than joined, for the reason in ensureDirPath.
		target = parent + "/" + target
	}
	return ensureDirPath(rootFd, target, depth+1)
}

func readlinkAt(dirFd int, name string) (string, error) {
	for size := 256; size <= unix.PathMax; size *= 2 {
		buf := make([]byte, size)
		n, err := retryOnEINTR2(func() (int, error) {
			return unix.Readlinkat(dirFd, name, buf)
		})
		if err != nil {
			return "", err
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
	return "", fmt.Errorf("symbolic link target of %s is too long", name)
}

// writeRenameAt writes content to name inside dirFd via a temporary file and
// rename(2), so nothing observes a partially written file. Mirrors
// fileutils.WriteRename, except that every step is relative to dirFd: the
// directory was resolved once, under RESOLVE_IN_ROOT, and no step here walks a
// path a symlink could redirect.
func writeRenameAt(dirFd int, name string, content []byte, mode os.FileMode) error {
	tmp, fd, err := createTempAt(dirFd)
	if err != nil {
		return err
	}
	defer func() {
		if tmp != "" {
			unix.Unlinkat(dirFd, tmp, 0) //nolint:errcheck // cleanup of a failed write
		}
	}()

	// Mode before the sync, so the file's permissions are part of the state
	// that reaches the disk, and before the rename, so the file is never
	// visible under its final name with the temporary's mode.
	if err := writeAndSync(fd, content, mode); err != nil {
		unix.Close(fd) //nolint:errcheck // the write already failed
		return fmt.Errorf("failed to write %s: %w", name, err)
	}
	// Not retried on EINTR: on Linux the descriptor is released regardless,
	// so a retry could close an unrelated file.
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("failed to close %s: %w", name, err)
	}

	if err := retryOnEINTR(func() error {
		return unix.Renameat(dirFd, tmp, dirFd, name)
	}); err != nil {
		return fmt.Errorf("failed to rename %s into place: %w", name, err)
	}
	tmp = ""
	if err := retryOnEINTR(func() error { return unix.Fsync(dirFd) }); err != nil {
		return fmt.Errorf("failed to sync directory of %s: %w", name, err)
	}
	return nil
}

func writeAndSync(fd int, content []byte, mode os.FileMode) error {
	if err := writeAll(fd, content); err != nil {
		return err
	}
	if err := retryOnEINTR(func() error { return unix.Fchmod(fd, unixMode(mode)) }); err != nil {
		return err
	}
	return retryOnEINTR(func() error { return unix.Fsync(fd) })
}

// createTempAt creates a uniquely named file inside dirFd. O_NOFOLLOW because
// the name may already exist as a symlink planted in the image; with O_EXCL
// that is refused rather than followed.
//
// O_EXCL authenticates the inode it returns, not the name for the rest of the
// operation. A concurrent writer sharing the volume can replace the name
// afterwards, in which case the rename below publishes what that writer put
// there and the deferred cleanup unlinks it rather than our own file. Both stay
// inside the root, and such a writer can already write this tree, so this
// costs integrity of the published file and no more.
func createTempAt(dirFd int) (string, int, error) {
	flags := unix.O_CREAT | unix.O_EXCL | unix.O_WRONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	var lastErr error
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf(".cloudinit-tmp-%d-%d", os.Getpid(), tmpCounter.Add(1))
		fd, err := retryOnEINTR2(func() (int, error) {
			return unix.Openat(dirFd, name, flags, 0600)
		})
		if err == nil {
			return name, fd, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", -1, fmt.Errorf("failed to create temporary file: %w", err)
		}
		lastErr = err
	}
	return "", -1, fmt.Errorf("failed to create temporary file: %w", lastErr)
}

func writeAll(fd int, content []byte) error {
	for len(content) > 0 {
		n, err := unix.Write(fd, content)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		content = content[n:]
	}
	return nil
}

// unixMode converts mode the way os.Chmod does, so a permissions string keeps
// meaning exactly what it meant before the write moved to a descriptor.
func unixMode(mode os.FileMode) uint32 {
	m := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		m |= unix.S_ISUID
	}
	if mode&os.ModeSetgid != 0 {
		m |= unix.S_ISGID
	}
	if mode&os.ModeSticky != 0 {
		m |= unix.S_ISVTX
	}
	return m
}

// retryOnEINTR repeats f while a signal interrupts it.
//
// Applied wherever the os-package call this write path replaced retried: open,
// mkdir, readlink, chmod, fsync, write and rename all loop inside os (see
// ignoringEINTR there). The runtime preempts goroutines with SIGURG, and while
// its own handlers carry SA_RESTART, anything else in the process may install
// one without it -- pillar is a single process running every agent -- so the
// guarantee is not ours to make.
//
// close(2) is deliberately excluded: on Linux the descriptor is released even
// when it reports EINTR, so retrying could close an unrelated file.
func retryOnEINTR(f func() error) error {
	for {
		if err := f(); !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// retryOnEINTR2 is retryOnEINTR for a call that also returns a value.
func retryOnEINTR2[T any](f func() (T, error)) (T, error) {
	for {
		v, err := f()
		if !errors.Is(err, unix.EINTR) {
			return v, err
		}
	}
}
