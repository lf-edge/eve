// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kernelcmdline

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

func TestParse(t *testing.T) {
	// want maps a parameter name to every value it is given, in order: a bare
	// flag is one empty value, and nil means the name is absent. Has and Value
	// are checked against the same expectation.
	tests := []struct {
		name string
		line string
		str  string
		want map[string][]string
	}{
		{
			name: "EVE boot line",
			line: "BOOT_IMAGE=/boot/kernel console=ttyS0 console=hvc0 getty isolcpus=12-15,28-31\n",
			str:  "BOOT_IMAGE=/boot/kernel console=ttyS0 console=hvc0 getty isolcpus=12-15,28-31",
			want: map[string][]string{
				"BOOT_IMAGE": {"/boot/kernel"},
				"console":    {"ttyS0", "hvc0"},
				"getty":      {""},
				"isolcpus":   {"12-15,28-31"},
				"missing":    nil,
			},
		},
		{
			name: "value holding an equals sign, and an empty value",
			line: "root=PARTUUID=ad68 foo=",
			str:  "root=PARTUUID=ad68 foo=",
			want: map[string][]string{
				"root": {"PARTUUID=ad68"},
				"foo":  {""},
			},
		},
		{
			name: "quoted values",
			line: `dyndbg="file x.c +p" "eve_x=a b" plain`,
			str:  `dyndbg="file x.c +p" "eve_x=a b" plain`,
			want: map[string][]string{
				"dyndbg": {"file x.c +p"},
				"eve_x":  {"a b"},
				"plain":  {""},
			},
		},
		{
			name: "names match exactly",
			line: "eve_max_vcpusX=4 eve-max-vcpus=2 gettyX",
			str:  "eve_max_vcpusX=4 eve-max-vcpus=2 gettyX",
			want: map[string][]string{
				"eve_max_vcpus":  nil,
				"getty":          nil,
				"eve_max_vcpusX": {"4"},
			},
		},
		{
			name: "any whitespace separates",
			line: "\t a=1 \n  b=2\t",
			str:  "a=1 \n  b=2",
			want: map[string][]string{
				"a": {"1"},
				"b": {"2"},
			},
		},
		{
			name: "whitespace is the kernel's, byte by byte",
			// The kernel's isspace takes \t \n \v \f \r, space and the byte 0xa0,
			// so it splits U+00A0 (c2 a0) after its first byte, and does not
			// split at U+0085 or U+2003.
			line: "a=1\v\f\rb=2 c=3 d=4\u0085e=5 f=6 g=7 h=8\xa0i=9",
			str:  "a=1\v\f\rb=2 c=3 d=4\u0085e=5 f=6 g=7 h=8\xa0i=9",
			want: map[string][]string{
				"a": {"1"},
				"b": {"2\xc2"},
				"c": {"3"},
				"d": {"4\u0085e=5"},
				"e": nil,
				"f": {"6 g=7"},
				"g": nil,
				"h": {"8"},
				"i": {"9"},
			},
		},
		{
			name: "an equals sign first in the name is part of it",
			line: "=a=b == =",
			str:  "=a=b == =",
			want: map[string][]string{
				"=a": {"b"},
				"=":  {"", ""},
				"":   nil,
			},
		},
		{
			name: "an unterminated quote runs to the end of the line",
			line: `dyndbg="a getty x=1 `,
			str:  `dyndbg="a getty x=1`,
			want: map[string][]string{
				"dyndbg": {"a getty x=1 "},
				"getty":  nil,
				"x":      nil,
			},
		},
		{
			name: "quoted flag, and text after a closing quote",
			line: `"getty" a="b c"d "e"f`,
			str:  `"getty" a="b c"d "e"f`,
			want: map[string][]string{
				"getty": {""},
				"a":     {`b c"d`},
				`e"f`:   {""},
			},
		},
		{
			name: "-- ends the kernel's parameters",
			line: "a -- b=1",
			str:  "a -- b=1",
			want: map[string][]string{
				"a":  {""},
				"--": nil,
				"b":  nil,
			},
		},
		{
			name: "a quoted -- ends them too",
			line: `a "--" b`,
			str:  `a "--" b`,
			want: map[string][]string{
				"a": {""},
				"b": nil,
			},
		},
		{
			name: "-- with a value is a parameter",
			line: "--=x b",
			str:  "--=x b",
			want: map[string][]string{
				"--": {"x"},
				"b":  {""},
			},
		},
		{
			name: "empty line",
			line: "",
			str:  "",
			want: map[string][]string{
				"": nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Parse(tt.line)
			if got := c.String(); got != tt.str {
				t.Errorf("String() = %q, want %q", got, tt.str)
			}
			for name, values := range tt.want {
				if got := c.Values(name); !reflect.DeepEqual(got, values) {
					t.Errorf("Values(%q) = %q, want %q", name, got, values)
				}
				present := values != nil
				if got := c.Has(name); got != present {
					t.Errorf("Has(%q) = %v, want %v", name, got, present)
				}
				wantValue := ""
				if present {
					wantValue = values[len(values)-1]
				}
				if got, ok := c.Value(name); got != wantValue || ok != present {
					t.Errorf("Value(%q) = (%q, %v), want (%q, %v)",
						name, got, ok, wantValue, present)
				}
			}
		})
	}
}

func TestRead(t *testing.T) {
	// procfs ends the line with a newline that is not part of it; the space
	// inside the unterminated quote is.
	path := filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(path, []byte("eve_max_vcpus=2 getty a=\"b \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := read(path)
	if err != nil {
		t.Fatalf("read(%s): %v", path, err)
	}
	if got, ok := c.Value("eve_max_vcpus"); got != "2" || !ok {
		t.Errorf(`Value("eve_max_vcpus") = (%q, %v), want ("2", true)`, got, ok)
	}
	if !c.Has("getty") {
		t.Error(`Has("getty") = false, want true`)
	}
	if got, _ := c.Value("a"); got != "b " {
		t.Errorf(`Value("a") = %q, want "b "`, got)
	}

	c, err = read(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Error("read of a missing file: no error")
	}
	if c.String() != "" || c.Has("getty") {
		t.Errorf("read of a missing file gave %q, want an empty command line", c.String())
	}
}

// A failed read is tried again on the next call; a successful one is kept.
func TestCachedReaderRetriesAfterFailure(t *testing.T) {
	reads := 0
	r := &cachedReader{read: func() (Cmdline, error) {
		reads++
		if reads == 1 {
			return Cmdline{}, errors.New("too many open files")
		}
		return Parse("getty"), nil
	}}
	if _, err := r.get(); err == nil {
		t.Fatal("get after a failed read: no error")
	}
	for range 2 {
		if c, err := r.get(); err != nil || !c.Has("getty") {
			t.Fatalf("get = (%q, %v), want getty and no error", c.String(), err)
		}
	}
	if reads != 2 {
		t.Errorf("%d reads, want 2: the failed one and the one kept", reads)
	}
}

// Agents share one zedbox process, so the line is asked for concurrently; it is
// still read once. Run with -race.
func TestCachedReaderReadsOnce(t *testing.T) {
	var reads atomic.Int32
	r := &cachedReader{read: func() (Cmdline, error) {
		reads.Add(1)
		return Parse("getty"), nil
	}}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c, err := r.get(); err != nil || !c.Has("getty") {
				t.Errorf("get = (%q, %v), want getty and no error", c.String(), err)
			}
		}()
	}
	wg.Wait()
	if n := reads.Load(); n != 1 {
		t.Errorf("%d reads, want 1", n)
	}
}

func TestCurrent(t *testing.T) {
	want, wantErr := read("/proc/cmdline")
	got, err := Current()
	if got.String() != want.String() || (err == nil) != (wantErr == nil) {
		t.Errorf("Current() = (%q, %v), want what /proc/cmdline holds: (%q, %v)",
			got.String(), err, want.String(), wantErr)
	}
}
