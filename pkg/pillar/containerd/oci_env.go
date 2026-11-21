// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"fmt"
	"strings"
)

// ShimEnvManifest renders the environment file of a container which runs
// inside a shim VM. The init of that VM sources the file, so it is shell
// code: one export per variable. How a value is quoted depends on where the
// variable comes from.
//
// imageEnv are the variables of the image, as NAME=value. An image holds
// final values, so the container gets each one as it is, see ShellLiteral.
//
// userEnv are the variables of the user-data, as NAME=value. What a value
// means depends on the format of the user-data. In a plain NAME=value line it
// is the value itself, so the container gets it as it is, too. As an entry of
// runcmd in a cloud-config it is shell text, and with expandUserEnv the shell
// of the init expands it, see ShellExpanded. These variables come last: an
// expanded one can refer to the ones of the image, and they win where both
// set the same name.
func ShimEnvManifest(workdir string, imageEnv, userEnv []string, expandUserEnv bool) string {
	var manifest strings.Builder
	if workdir != "" {
		fmt.Fprintf(&manifest, "export WORKDIR=\"%s\"\n", workdir)
	}
	for _, e := range imageEnv {
		manifest.WriteString(exportLine(e, ShellLiteral))
	}
	quoteUserEnv := ShellLiteral
	if expandUserEnv {
		quoteUserEnv = ShellExpanded
	}
	for _, e := range userEnv {
		manifest.WriteString(exportLine(e, quoteUserEnv))
	}
	return manifest.String()
}

// exportLine renders the line which exports one variable, given as
// NAME=value, with its value quoted by quote. A variable which is given as
// its name only is exported as the shell has it.
func exportLine(entry string, quote func(string) string) string {
	name, value, hasValue := strings.Cut(entry, "=")
	if !hasValue {
		return fmt.Sprintf("export %s\n", entry)
	}
	return fmt.Sprintf("export %s=%s\n", name, quote(value))
}

// ShellLiteral quotes a value so that a shell takes it as it is: between
// single quotes, where no character has a meaning but the single quote.
func ShellLiteral(value string) string {
	return `'` + strings.ReplaceAll(value, `'`, `'\''`) + `'`
}

// ShellExpanded quotes a value so that a shell expands it and changes nothing
// else: between double quotes, where it replaces $NAME, $(command) and
// backquotes. A backslash in front of a dollar sign or of a backquote is not
// part of the value: it keeps that character as it is.
func ShellExpanded(value string) string {
	var quoted strings.Builder
	quoted.WriteByte('"')
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == '"':
			quoted.WriteString(`\"`)
		case c == '\\' && i+1 < len(value) && (value[i+1] == '$' || value[i+1] == '`'):
			quoted.WriteByte(c)
			quoted.WriteByte(value[i+1])
			i++
		case c == '\\':
			quoted.WriteString(`\\`)
		default:
			quoted.WriteByte(c)
		}
	}
	quoted.WriteByte('"')
	return quoted.String()
}

// envManifest renders the environment file for the shim VM of the container.
// The variables which UpdateEnvVar has added are the ones of the user-data,
// all others are the ones of the image.
func (s *ociSpec) envManifest() string {
	fromImage := len(s.Process.Env) - len(s.userEnv)
	if fromImage < 0 {
		fromImage = 0
	}
	return ShimEnvManifest(s.Process.Cwd, s.Process.Env[:fromImage], s.Process.Env[fromImage:], s.expandUserEnv)
}
