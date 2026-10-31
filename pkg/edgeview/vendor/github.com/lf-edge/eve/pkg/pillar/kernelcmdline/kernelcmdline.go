// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package kernelcmdline is the one place pillar reads the kernel command line.
// It parses the line exactly as the kernel parses its own parameters
// (parse_args in kernel/params.c, next_arg in lib/cmdline.c), so every agent
// asking about a boot parameter gets the answer the kernel would give.
package kernelcmdline

import (
	"os"
	"strings"
	"sync"
)

// Cmdline is a parsed kernel command line. The zero value is an empty one.
type Cmdline struct {
	line   string
	params []param
}

// param is one parameter. A bare flag has no value, which Value reports as an
// empty one.
type param struct {
	name     string
	value    string
	hasValue bool
}

// cachedReader reads the command line once and keeps the result: the line is
// fixed for the whole boot. A failed read is not kept, so the next call tries
// again.
type cachedReader struct {
	read   func() (Cmdline, error)
	mu     sync.Mutex
	parsed *Cmdline
}

func (r *cachedReader) get() (Cmdline, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.parsed != nil {
		return *r.parsed, nil
	}
	c, err := r.read()
	if err != nil {
		return Cmdline{}, err
	}
	r.parsed = &c
	return c, nil
}

var current = &cachedReader{read: func() (Cmdline, error) {
	return read("/proc/cmdline")
}}

// Current returns the command line the running kernel was booted with, read
// once per process. When it cannot be read, it returns the error and an empty
// Cmdline, in which nothing is present, and the next call reads it again.
func Current() (Cmdline, error) {
	return current.get()
}

func read(path string) (Cmdline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Cmdline{}, err
	}
	// procfs ends the line with a newline that is not part of it.
	return Parse(strings.TrimSuffix(string(data), "\n")), nil
}

// Parse parses a kernel command line the way the kernel parses its own
// parameters:
//   - parameters are separated by the bytes the kernel's isspace accepts;
//   - double quotes keep spaces inside a parameter: name="a b" and "name=a b"
//     both set name to a b;
//   - a parameter is split at its first '=' after its first byte;
//   - a bare -- ends the kernel's parameters, and what follows it is not one.
func Parse(line string) Cmdline {
	c := Cmdline{line: strings.TrimSpace(line)}
	rest := skipSpaces(line)
	for rest != "" {
		end := tokenEnd(rest)
		p := parseParam(rest[:end])
		if p.name == "--" && !p.hasValue {
			break
		}
		c.params = append(c.params, p)
		rest = skipSpaces(rest[end:])
	}
	return c
}

// tokenEnd returns where the parameter s starts with ends: at its first space
// outside double quotes.
func tokenEnd(s string) int {
	inQuote := false
	for i := 0; i < len(s); i++ {
		if !inQuote && isSpace(s[i]) {
			return i
		}
		if s[i] == '"' {
			inQuote = !inQuote
		}
	}
	return len(s)
}

func skipSpaces(s string) string {
	for s != "" && isSpace(s[0]) {
		s = s[1:]
	}
	return s
}

// isSpace is the kernel's isspace, which works on bytes: its ctype table marks
// \t \n \v \f \r, space and 0xa0 as space.
func isSpace(b byte) bool {
	return b == ' ' || (b >= '\t' && b <= '\r') || b == 0xa0
}

// parseParam splits one parameter at its first '=' after the first byte and
// drops the quotes the kernel drops: a leading quote of the parameter or of the
// value and, when one of those was dropped, one trailing quote.
func parseParam(token string) param {
	token, quoted := strings.CutPrefix(token, `"`)
	eq := -1
	if token != "" {
		if i := strings.IndexByte(token[1:], '='); i >= 0 {
			eq = i + 1
		}
	}
	if eq < 0 {
		if quoted {
			token = strings.TrimSuffix(token, `"`)
		}
		return param{name: token}
	}
	value, valueQuoted := strings.CutPrefix(token[eq+1:], `"`)
	if quoted || valueQuoted {
		value = strings.TrimSuffix(value, `"`)
	}
	return param{name: token[:eq], value: value, hasValue: true}
}

// String returns the command line as the kernel reported it, without
// surrounding whitespace.
func (c Cmdline) String() string {
	return c.line
}

// Has reports whether the parameter is present, as a bare flag or with a value.
// Names match exactly.
func (c Cmdline) Has(name string) bool {
	_, ok := c.Value(name)
	return ok
}

// Value returns the value of the parameter's last occurrence, which is the one
// that takes effect; a bare flag has an empty value. ok is false when the
// parameter is absent.
func (c Cmdline) Value(name string) (value string, ok bool) {
	for i := len(c.params) - 1; i >= 0; i-- {
		if c.params[i].name == name {
			return c.params[i].value, true
		}
	}
	return "", false
}

// Values returns the values of every occurrence of the parameter, in order,
// for parameters that may be given more than once, such as console. It is nil
// when the parameter is absent.
func (c Cmdline) Values(name string) []string {
	var values []string
	for _, p := range c.params {
		if p.name == name {
			values = append(values, p.value)
		}
	}
	return values
}
