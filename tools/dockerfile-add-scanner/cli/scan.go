package cli

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

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
)

const (
	defaultNamespace = "https://github.com/lf-edge/eve/spdx"
	creator          = "https://github.com/lf-edge/eve/tools/dockerfile-add-scanner"
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
		name := filepath.Base(u.Path)
		pkg := &spdx.Package{
			PackageName:             name,
			PackageSPDXIdentifier:   spdxcommon.MakeDocElementID("Package", name).ElementRefID,
			PackageDownloadLocation: u.String(),
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
