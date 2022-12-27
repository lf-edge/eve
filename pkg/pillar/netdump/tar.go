package netdump

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"strings"
	"time"
)

type fileForTar struct {
	dstPath string
	info    fs.FileInfo
	isDir   bool
	content io.Reader
}

// Create .tar.gz archive at the location <tarPath> containing <files> inside.
func createTarGz(tarPath string, files []fileForTar) (err error) {
	tarFile, err := os.Create(tarPath)
	if err != nil {
		return fmt.Errorf("netdump: failed to create tar archive file %s: %w",
			tarPath, err)
	}
	defer tarFile.Close()
	gz := gzip.NewWriter(tarFile)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	for _, file := range files {
		var hdr *tar.Header
		content := file.content
		if file.info != nil {
			hdr, err = tar.FileInfoHeader(file.info, file.info.Name())
			if err != nil {
				return fmt.Errorf("netdump: failed to get tar.Header from file (%s) info: %w",
					file.dstPath, err)
			}
		} else {
			now := time.Now()
			hdr = &tar.Header{
				Uid:        os.Getuid(),
				Gid:        os.Getgid(),
				ModTime:    now,
				AccessTime: now,
				ChangeTime: now,
			}
			if file.isDir {
				hdr.Typeflag = tar.TypeDir
				hdr.Mode = 0755 | int64(os.ModeDir)
			} else {
				hdr.Typeflag = tar.TypeReg
				hdr.Mode = 0664
				if file.content != nil {
					buf := new(strings.Builder)
					hdr.Size, err = io.Copy(buf, file.content)
					if err != nil {
						return fmt.Errorf("netdump: failed to read file (%s) content: %w",
							file.dstPath, err)
					}
					content = strings.NewReader(buf.String())
				}
			}
			if whoami, err := user.Current(); err == nil {
				hdr.Uname = whoami.Username
				if group, err := user.LookupGroupId(whoami.Gid); err == nil {
					hdr.Gname = group.Name
				}
			}
		}
		hdr.Name = file.dstPath
		err = tw.WriteHeader(hdr)
		if err != nil {
			return fmt.Errorf("netdump: failed to write tar header for file %s: %w",
				file.dstPath, err)
		}
		if file.isDir {
			continue
		}
		if content != nil {
			_, err = io.Copy(tw, content)
			if err != nil {
				return fmt.Errorf("netdump: failed to copy file (%s) content: %w",
					file.dstPath, err)
			}
		}
	}
	return nil
}
