// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier:: Apache-2.0

package pkg

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/config"
)

// trick to not confuse spdx check shellscript
const spdxLicenseIdentifier = "SPDX-" + "License-Identifier:"

type LintSpdx struct {
	extsMap      map[string]func(path string)
	organization string
}

func (s *LintSpdx) dontfix(path string) {
	log.Printf("Cannot fix %s ...\n", path)
}

func (s *LintSpdx) copyright(commentIndicator string) []string {
	copyrightLines := []string{
		fmt.Sprintf("%s Copyright (c) %d %s, Inc.\n", commentIndicator, time.Now().Year(), s.organization),
		fmt.Sprintf("%s %s: Apache-2.0\n\n", commentIndicator, spdxLicenseIdentifier),
	}

	return copyrightLines
}

func (s *LintSpdx) yamlfix(path string) {
	log.Printf("Fixing %s ...\n", path)
	prepend(path, s.copyright("#"))
}

func (s *LintSpdx) gofix(path string) {
	log.Printf("Fixing %s ...\n", path)
	prepend(path, s.copyright("//"))
}

func (s *LintSpdx) dockerfilefix(path string) {
	log.Printf("Fixing %s ...\n", path)
	prepend(path, s.copyright("#"))
}

func prepend(path string, license []string) {
	backupFh, err := os.CreateTemp("/var/tmp", "git-change-exec-spdx-fix")
	if err != nil {
		log.Fatalf("could not create temp file: %v", err)
	}
	backupPath := backupFh.Name()
	defer os.Remove(backupPath)

	for _, line := range license {
		fmt.Fprint(backupFh, line)
	}

	origFh, err := os.Open(path)
	if err != nil {
		log.Fatalf("could not open original file %s: %v", path, err)
	}

	_, err = io.Copy(backupFh, origFh)
	if err != nil {
		log.Fatalf("could not copy: %v", err)
	}

	backupFh.Close()
	origFh.Close()

	err = copyFile(backupPath, path)
	if err != nil {
		log.Fatalf("could not rename %s -> %s: %v", backupPath, path, err)
	}

}

func readGitConfigOrganization() string {
	cfg, err := config.LoadConfig(config.GlobalScope)
	if err != nil {
		panic(err)
	}

	for _, sec := range cfg.Raw.Sections {
		if sec.Name != "user" {
			continue
		}
		// codespell:ignore
		organizations := sec.OptionAll("organization")

		for _, organization := range organizations {
			if organization != "" {
				return organization
			}
		}
	}

	return ""
}

func (s *LintSpdx) init() {
	s.extsMap = map[string]func(path string){
		".sh":        s.dontfix,
		".go":        s.gofix,
		".c":         s.dontfix,
		".h":         s.dontfix,
		".py":        s.dontfix,
		".rs":        s.dontfix,
		".yaml":      s.yamlfix,
		".yml":       s.yamlfix,
		"Dockerfile": s.dockerfilefix,
	}

	s.organization = readGitConfigOrganization()

}

func (s *LintSpdx) pathMatch(path string) (func(path string), bool) {
	f, found := s.extsMap[filepath.Ext(path)]
	if !found {
		f, found = s.extsMap[filepath.Base(path)]
	}

	return f, found
}

func (s *LintSpdx) hasSpdx(path string) bool {
	scriptPath := "tools/spdx-check.sh"

	cmd := exec.Command(scriptPath, path)

	bs, err := cmd.CombinedOutput()
	if err == nil {
		return true
	}

	exitErr, ok := err.(*exec.ExitError)

	if ok {
		return strings.Contains(string(bs), spdxLicenseIdentifier+" OK")
	}

	log.Fatalf("running '%s' '%s' failed: %v", scriptPath, path, exitErr)

	return false

}

func (s *LintSpdx) MatchPath(path string) bool {
	if s.extsMap == nil {
		s.init()
	}

	if strings.Contains(path, "/vendor/") {
		return false
	}
	_, found := s.pathMatch(path)
	if !found {
		return false
	}
	if !s.hasSpdx(path) {
		return true
	}

	return false
}

func (s *LintSpdx) Id() string {
	return "gce:lint-spdx"
}

func (s *LintSpdx) Do(actionToDos []ActionToDo) error {
	if s.extsMap == nil {
		s.init()
	}

	if s.organization == "" {
		return fmt.Errorf("could not read organization from git config, cannot fix copyrights")
	}

	for _, atd := range actionToDos {
		extFixFunc, found := s.pathMatch(atd.Path)
		if !found {
			continue
		}

		extFixFunc(atd.Path)
	}

	return nil
}

func (s *LintSpdx) Close() {
}

func copyFile(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)

	return err
}
