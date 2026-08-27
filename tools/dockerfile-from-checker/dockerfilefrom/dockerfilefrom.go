// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package dockerfilefrom extracts the base image references of a
// Dockerfile's FROM instructions, substituting ${ARG} with defaults
// declared before the first FROM.
//
// The parser is self-contained on purpose, so this tool does not have to
// track the version of moby/buildkit, whose Dockerfile frontend is pulled
// in transitively by linuxkit's pkglib and pins old package versions. It
// mirrors the subset of buildkit's parser behavior that the EVE
// hash-consistency checks depend on: meta-ARG scope, valueless-ARG
// redeclaration, and line-continuation semantics.
package dockerfilefrom

import (
	"bufio"
	"io"
	"strings"
)

// Result holds what a Dockerfile scan found.
type Result struct {
	// FromSet is the base image reference of each FROM instruction, in
	// order, after ${ARG} substitution. An undefined or empty variable
	// leaves the literal `${ARG}` intact (or yields an empty string when
	// the ARG resolves to nothing).
	FromSet []string
	// Args holds the ARG defaults declared before the first FROM line,
	// mirroring buildkit meta-ARG handling: a valueless ARG records the
	// empty string only when the name is new; a valued redeclaration
	// replaces the previous default. ARGs declared after the first FROM
	// (stage-level) are omitted.
	Args map[string]string
}

// Scan reads a Dockerfile and returns its FROM base image references.
// It does not fail on Dockerfile syntax; the only error it can return is
// a read error from r.
func Scan(r io.Reader) (*Result, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	content := strings.TrimPrefix(string(data), "\ufeff")

	escape := "\\"
	if strings.HasPrefix(content, "# escape=") {
		// the directive line itself ends with the escape character, so
		// consume it before the line-continuation pass
		if d := escapeDirective(content); d != "" {
			escape = d
		}
		idx := strings.IndexByte(content, '\n')
		if idx < 0 {
			idx = len(content)
		}
		content = content[idx+1:]
	}

	// Logical lines: physical lines joined by a trailing escape character,
	// exactly as buildkit's parser does it:
	//   - the first physical line is left-trimmed, later ones are not
	//   - a trailing escape plus trailing spaces continues the line
	//   - continuation lines are appended raw, indentation preserved
	//   - comment and empty lines inside a continuation are skipped
	var logical []string
	sc := bufio.NewScanner(strings.NewReader(content))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	isComment := func(s string) bool {
		return strings.HasPrefix(strings.TrimSpace(s), "#")
	}
	inCont := false
	var b strings.Builder
	for sc.Scan() {
		l := strings.TrimSuffix(sc.Text(), "\r")
		cont, l2 := stripTrailingEscape(l, escape)
		if inCont {
			if isComment(l) || strings.TrimSpace(l) == "" {
				continue
			}
		} else if isComment(l) || l == "" {
			if cont {
				// a line that is only the escape char
				b.WriteString(l2)
				inCont = true
			}
			continue
		} else {
			l2 = strings.TrimLeft(l2, " \t")
		}
		b.WriteString(l2)
		if !cont {
			logical = append(logical, b.String())
			b.Reset()
		}
		inCont = cont
	}
	if inCont {
		logical = append(logical, b.String())
	}

	res := &Result{Args: make(map[string]string)}

	// Args before the first FROM (level meta args), in declaration order.
	metaDone := false
	for _, line := range logical {
		fields := strings.Fields(line)
		if len(fields) == 0 || metaDone {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "ARG":
			remainder := strings.TrimSpace(line[len(fields[0]):])
			name, val, hasVal := strings.Cut(remainder, "=")
			name = strings.TrimSpace(name)
			if hasVal {
				res.Args[name] = strings.TrimSpace(val)
			} else if _, seen := res.Args[name]; !seen {
				res.Args[name] = ""
			}
		case "FROM":
			metaDone = true
		}
	}

	// FROM base image references, skipping flags (`FROM --platform=...`).
	for _, line := range logical {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.ToUpper(fields[0]) != "FROM" {
			continue
		}
		for _, tok := range fields[1:] {
			if strings.HasPrefix(tok, "--") {
				continue
			}
			res.FromSet = append(res.FromSet, expandVar(tok, res.Args))
			break
		}
	}

	return res, nil
}

// escapeDirective returns the escape character declared by a leading
// `# escape=` directive. Per the Dockerfile spec both `\` and a backtick
// are valid; any other value (or no directive) yields "", meaning "use
// the default backslash".
func escapeDirective(content string) string {
	if !strings.HasPrefix(content, "# escape=") {
		return ""
	}
	idx := strings.IndexByte(content, '\n')
	if idx < 0 {
		idx = len(content)
	}
	fields := strings.Fields(content[:idx])
	if len(fields) != 2 || fields[0] != "#" || !strings.HasPrefix(fields[1], "escape=") {
		return ""
	}
	switch v := fields[1][len("escape="):]; v {
	case "\\", "`":
		return v
	}
	return ""
}

// stripTrailingEscape reports whether s ends in a line-continuation escape
// (an odd trailing run) and returns s with that escape and any trailing
// spaces removed.
func stripTrailingEscape(s, escape string) (bool, string) {
	if escape == "" {
		return false, s
	}
	t := strings.TrimRight(s, " \t")
	n := 0
	for i := len(t) - 1; i >= 0 && t[i] == escape[0]; i-- {
		n++
	}
	if n%2 == 1 {
		return true, t[:len(t)-1]
	}
	return false, s
}

// expandVar substitutes ${key} with val. The plain `$key` form and any
// undefined ${key} are left intact, matching the checker's original
// behavior.
func expandVar(from string, vars map[string]string) string {
	for key, val := range vars {
		from = strings.ReplaceAll(from, "${"+key+"}", val)
	}
	return from
}

// Expand substitutes the ${name} and $name references in word using
// lookup, which reports whether a name is defined. An undefined name
// yields the empty string; a backslash escapes the following character.
//
// It mirrors the word expansion of buildkit's frontend shell lexer for
// plain reference forms, without its quote stripping or ${name:...}
// modifier syntax, which the EVE Dockerfiles do not use.
func Expand(word string, lookup func(name string) (string, bool)) string {
	var b strings.Builder
	for i := 0; i < len(word); {
		switch word[i] {
		case '\\':
			if i+1 < len(word) {
				i++
				b.WriteByte(word[i])
			}
			i++
		case '$':
			if i+1 < len(word) && word[i+1] == '{' {
				end := strings.IndexByte(word[i+2:], '}')
				if end < 0 {
					b.WriteByte('$')
					i++
					continue
				}
				if v, ok := lookup(word[i+2 : i+2+end]); ok {
					b.WriteString(v)
				}
				i += end + 3
				continue
			}
			name := scanName(word[i+1:])
			if name == "" {
				b.WriteByte('$')
				i++
				continue
			}
			if v, ok := lookup(name); ok {
				b.WriteString(v)
			}
			i += 1 + len(name)
		default:
			b.WriteByte(word[i])
			i++
		}
	}
	return b.String()
}

func scanName(s string) string {
	i := 0
	for i < len(s) && isNameChar(s[i]) {
		i++
	}
	return s[:i]
}

func isNameChar(c byte) bool {
	return c == '_' ||
		c >= 'a' && c <= 'z' ||
		c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9'
}
