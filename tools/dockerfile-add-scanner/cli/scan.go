// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/google/licensecheck"
	"github.com/google/uuid"
	"github.com/moby/buildkit/frontend/dockerfile/dockerfile2llb"
	"github.com/moby/buildkit/solver/pb"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
	spdxjson "github.com/spdx/tools-golang/json"
	spdxcommon "github.com/spdx/tools-golang/spdx/common"
	spdx "github.com/spdx/tools-golang/spdx/v2_3"
	spdxtv "github.com/spdx/tools-golang/tvsaver"
	"github.com/spf13/cobra"
	"github.com/ulikunitz/xz"
)

const (
	defaultNamespace   = "https://github.com/lf-edge/eve/spdx"
	creator            = "https://github.com/lf-edge/eve/tools/dockerfile-add-scanner"
	coverageThreshold  = 75
	unknownLicenseType = "UNKNOWN"
)

var (
	githubDownloadRegex = regexp.MustCompile(`tarball/([^\/]+)$`)
	kernelDownloadRegex = regexp.MustCompile(`/linux-(\d+\.\d+\.\d+)\.tar\.[a-z]+$`)
)

func scanCmd() *cobra.Command {
	var (
		outputFormat string
		namespace    string
		arch         string
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan Dockerfiles for ADD commands",
		Long: `Scan Dockerfiles for ADD commands and print the URLs to stdout.
	Can scan multiple at once. Output can be in list, spdx or spdx-json formats.
`,
		Example: `dockerfile-add-scanner scan <dockerfile1> <dockerfile2> ... <dockerfileN>`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var allUrls []*url.URL
			for _, dockerfile := range args {
				log.Debugf("Processing %s", dockerfile)
				urls, err := scan(dockerfile, arch)
				if err != nil {
					log.Fatalf("Error scanning %s: %v", dockerfile, err)
				}
				allUrls = append(allUrls, urls...)
			}
			switch outputFormat {
			case "list":
				for _, u := range allUrls {
					fmt.Println(u.String())
				}
			case "spdx":
				sbom, err := buildSbom(allUrls, namespace, creator)
				if err != nil {
					return err
				}
				return spdxtv.Save2_3(sbom, os.Stdout)
			case "spdx-json":
				sbom, err := buildSbom(allUrls, namespace, creator)
				if err != nil {
					return err
				}
				return spdxjson.Save2_3(sbom, os.Stdout)
			default:
				return fmt.Errorf("unknown output format %s", outputFormat)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&outputFormat, "format", "list", "Output format: list, spdx, spdx-json")
	cmd.Flags().StringVar(&namespace, "namespace", defaultNamespace, "document namespace to use for spdx output formats, will have a UUID appended")
	cmd.Flags().StringVar(&arch, "arch", runtime.GOARCH, "architecture for which it would be built, defaults to current platform")

	return cmd
}

func scan(dockerfile, arch string) ([]*url.URL, error) {
	var urls []*url.URL
	f, err := os.Open(dockerfile)
	if err != nil {
		return nil, fmt.Errorf("error opening dockerfile %s: %v", dockerfile, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("error reading dockerfile at %s: %v", dockerfile, err)
	}

	ctx := context.TODO()

	// this method strips out all comments. We might want some of the comments, which
	// github.com/moby/buildkit/frontend/dockerfile/parser.Parse() gives us, but then it does not
	// resolve the various variables.
	state, _, _, err := dockerfile2llb.Dockerfile2LLB(ctx, data, dockerfile2llb.ConvertOpt{
		TargetPlatform: &ocispecs.Platform{Architecture: arch, OS: "linux"},
	})
	if err != nil {
		return nil, err
	}
	def, err := state.Marshal(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range def.Def {
		var op pb.Op
		if err := op.Unmarshal(d); err != nil {
			return nil, err
		}
		src := op.GetSource()
		if src == nil {
			continue
		}
		identifier := src.GetIdentifier()
		if identifier == "" {
			continue
		}
		parsed, err := url.Parse(identifier)
		if err != nil {
			return nil, fmt.Errorf("unable to parse url %s: %v", identifier, err)
		}
		switch parsed.Scheme {
		case "http", "https", "ftp", "ftps", "git":
			urls = append(urls, parsed)
		}
	}

	return urls, nil
}

func buildSbom(urls []*url.URL, namespace, creator string) (*spdx.Document, error) {
	var packages []*spdx.Package
	for _, u := range urls {
		// what do we want to add?
		// - PackageLicenseConcluded
		// - PackageLicenseDeclared
		// - PackageCopyrightText

		// we have some logic about versions
		name := filepath.Base(u.Path)
		pkg := &spdx.Package{
			PackageName:             name,
			PackageSPDXIdentifier:   spdxcommon.MakeDocElementID("Package", name).ElementRefID,
			PackageDownloadLocation: u.String(),
			PackageLicenseConcluded: "NOASSERTION",
			PackageLicenseDeclared:  "NONE",
			PackageExternalReferences: []*spdx.PackageExternalReference{
				{Category: "PACKAGE-MANAGER", RefType: "purl", Locator: fmt.Sprintf("pkg:generic/generic?download_url=%s", u.String())},
			},
		}
		version := getVersionFromURL(u)
		if version != "" {
			pkg.PackageVersion = version
		}
		licenseDeclared, licenseConcluded := getLicenseFromURL(u)
		if licenseDeclared != "" {
			pkg.PackageLicenseDeclared = licenseDeclared
		}
		if licenseConcluded != "" {
			pkg.PackageLicenseConcluded = licenseConcluded
		}

		// could we get a version from the URL?
		if (u.Scheme == "git" || strings.HasSuffix(name, ".git")) && u.Fragment != "" {
			pkg.PackageVersion = u.Fragment
		}

		packages = append(packages, pkg)
	}
	return &spdx.Document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXIdentifier:    "DOCUMENT",
		DocumentName:      "dockerfile",
		DocumentNamespace: fmt.Sprintf("%s-%s", namespace, uuid.New()),

		CreationInfo: &spdx.CreationInfo{
			Created: time.Now().UTC().Format(time.RFC3339),
			Creators: []spdxcommon.Creator{
				{Creator: creator, CreatorType: "Tool"},
			},
		},
		Packages: packages,
	}, nil
}

// getVersionFromURL try to determine version from URL
func getVersionFromURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	// git protocol means the whole thing, no implicit version
	if u.Scheme == "git" || strings.HasSuffix(u.Path, ".git") {
		return ""
	}
	if u.Host == "github.com" && githubDownloadRegex.MatchString(u.Path) {
		return githubDownloadRegex.FindStringSubmatch(u.Path)[1]
	}
	if u.Host == "www.kernel.org" && kernelDownloadRegex.MatchString(u.Path) {
		return kernelDownloadRegex.FindStringSubmatch(u.Path)[1]
	}
	return ""
}

// getLicenseFromURL try to determine license from URL
func getLicenseFromURL(u *url.URL) (string, string) {
	if u == nil {
		return "", ""
	}
	// tmpdir to save our files
	tmpDir, err := os.MkdirTemp("", "sbom")
	if err != nil {
		return "", ""
	}
	defer os.RemoveAll(tmpDir)

	// git protocol means clone the whole thing
	switch {
	case u.Scheme == "git" || strings.HasSuffix(u.Path, ".git"):
		_, err := git.PlainClone(tmpDir, false, &git.CloneOptions{
			URL:      u.String(),
			Progress: os.Stderr,
		})
		if err != nil {
			return "", ""
		}

	case u.Host == "github.com" && githubDownloadRegex.MatchString(u.Path):
		// it is a tgz file, so we should be able to scan it
		var gz *gzip.Reader
		err = extractURLToPath(u, tmpDir, func(r io.Reader) (io.Reader, error) {
			gz, err = gzip.NewReader(r)
			return gz, err
		})
		if err != nil {
			return "", ""
		}
		defer gz.Close()
	case u.Host == "www.kernel.org" && kernelDownloadRegex.MatchString(u.Path):
		// it is a .tar.xz file, so we should be able to scan it
		err = extractURLToPath(u, tmpDir, func(r io.Reader) (io.Reader, error) {
			return xz.NewReader(r)
		})
		if err != nil {
			return "", ""
		}
	default:
		return "", ""
	}
	// directory contains everything, so go look for files
	var licenses []string
	fsys := os.DirFS(tmpDir)
	err = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// ignore git directory
		if path == ".git" || strings.HasPrefix(path, ".git/") {
			return nil
		}
		switch {
		case d.IsDir():
			return nil
		case d.Type() == fs.ModeSymlink:
			// ignore them
			return nil
		default:
			// make sure it is not vendored
			filename := filepath.Base(path)
			// ignore any that are not a known filetype
			if _, ok := licenseFileNames[filename]; !ok {
				return nil
			}
			parts := strings.Split(filepath.Dir(path), string(filepath.Separator))
			for _, part := range parts {
				if part == "vendor" {
					return nil
				}
			}
			// it is a file wioth the right name not in a vendor path
			r, err := fsys.Open(path)
			if err != nil {
				return err
			}
			defer r.Close()
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, r); err != nil {
				return err
			}
			cov := licensecheck.Scan(buf.Bytes())

			if cov.Percent < float64(coverageThreshold) {
				licenses = append(licenses, unknownLicenseType)
			}
			for _, m := range cov.Match {
				licenses = append(licenses, m.ID)
			}
			return nil
		}
	})
	if err != nil {
		return "", ""
	}
	if len(licenses) == 0 {
		return "", ""
	}
	// declared is all of them, but made unique
	var (
		uniqueLicenses []string
		m              = make(map[string]bool)
	)
	for _, l := range licenses {
		if _, ok := m[l]; !ok {
			m[l] = true
			uniqueLicenses = append(uniqueLicenses, l)
		}
	}

	licensesDeclared := strings.Join(uniqueLicenses, " AND ")
	// concluded is the most relevant. Somewhat arbitrarily, we take the first that is not unknown
	var licenseConcluded string
	for _, l := range uniqueLicenses {
		if l != unknownLicenseType {
			licenseConcluded = l
			break
		}
	}
	if licenseConcluded == "" {
		licenseConcluded = unknownLicenseType
	}
	return licensesDeclared, licenseConcluded

}

type decompress func(io.Reader) (io.Reader, error)

func extractURLToPath(u *url.URL, path string, decompress decompress) error {
	// it is a tgz file, so we should be able to scan it
	res, err := http.Get(u.String())
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil
	}
	// gunzip and untar the file
	dr, err := decompress(res.Body)
	if err != nil {
		return err
	}
	tr := tar.NewReader(dr)
	for {
		header, err := tr.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(filepath.Join(path, header.Name), 0755); err != nil {
				log.Fatalf("extract: Mkdir() failed: %s", err.Error())
			}
		case tar.TypeReg:
			outFile, err := os.Create(filepath.Join(path, header.Name))
			if err != nil {
				log.Fatalf("extract: Create() failed: %s", err.Error())
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				log.Fatalf("extract: Copy() failed: %s", err.Error())
			}
			outFile.Close()
		}
	}
	return nil
}
