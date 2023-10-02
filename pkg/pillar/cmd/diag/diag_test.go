// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bufio"
	"fmt"
	"os"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var (
	string9   = "012345678"
	string10  = "0123456789"
	string11  = "0123456789X"
	string9n  = string9 + "\n"
	string10n = string10 + "\n"
	string11n = string11 + "\n"
	string9a  = "abcdefghi\n"
	string10a = "abcdefghij\n"
	string11a = "abcdefghijk\n"
	string9A  = "ABCDEFGHI\n"
	string10A = "ABCDEFGHIJ\n"
	string11A = "ABCDEFGHIJK\n"
	leading9  = "\n" + string9a
	trailing9 = string9A + "\n"
	fmt1      = "%s\n"
	fmt2      = "%s %s\n"
	fmt3      = "%s %s %s\n"
	longest   = "012345678901234567890123456789" // Wraps to 10x3
	toolong   = longest + "x"
)

func TestPrintIfSpace(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "diag", 0)
	outfile := os.Stdout
	stateFilename := ""
	maxRows := 3 + 1 // Add one for any Exceeded output
	maxColumns := 10

	type printArg struct {
		format string
		args   []interface{}
	}
	type printArgs struct {
		sequence []printArg
		expected bool // Checked on last call only
	}
	printTests := map[string]printArgs{
		"threeFits": {
			sequence: []printArg{
				{format: string9n},
				{format: string9a},
				{format: string9A},
			},
			expected: true,
		},
		"threeFitsExact": {
			sequence: []printArg{
				{format: string10n},
				{format: string10a},
				{format: string10A},
			},
			expected: true,
		},
		"threeFitsExactPlus": {
			sequence: []printArg{
				{format: string10n},
				{format: string10a},
				{format: string11A},
			},
			expected: false,
		},
		"fourFail": {
			sequence: []printArg{
				{format: string9n},
				{format: string9a},
				{format: string9A},
				{format: string9n},
			},
			expected: false,
		},
		"wrapThree": {
			sequence: []printArg{
				{format: string11n},
				{format: string9a},
				{format: string9A},
			},
			expected: false,
		},
		"leadingTwo": {
			sequence: []printArg{
				{format: leading9},
				{format: string9n},
			},
			expected: true,
		},
		"leadingThree": {
			sequence: []printArg{
				{format: leading9},
				{format: string9A},
				{format: string9a},
			},
			expected: false,
		},
		"trailingTwo": {
			sequence: []printArg{
				{format: string9n},
				{format: trailing9},
			},
			expected: true,
		},
		"trailingThree": {
			sequence: []printArg{
				{format: string9n},
				{format: string9a},
				{format: trailing9},
			},
			expected: false,
		},
		"fmtTwo": {
			sequence: []printArg{
				{
					format: fmt2,
					args:   []interface{}{string11, string11},
				},
			},
			expected: true,
		},
		"fmtThree": {
			sequence: []printArg{
				{
					format: fmt3,
					args:   []interface{}{string9, string9, string10},
				},
			},
			expected: true,
		},
		"fmtThreePlus": {
			sequence: []printArg{
				{
					format: fmt3,
					args:   []interface{}{string9, string10, string10},
				},
			},
			expected: false,
		},
		"fmtwrap": {
			sequence: []printArg{
				{
					format: fmt2,
					args:   []interface{}{string10, string9a},
				},
			},
			expected: true,
		},
		"longest": {
			sequence: []printArg{
				{format: longest},
			},
			expected: true,
		},
		"too long": {
			sequence: []printArg{
				{format: toolong},
			},
			expected: false,
		},
	}

	h := PrintIfSpaceInit(outfile, stateFilename,
		maxRows, maxColumns)
	for testname, test := range printTests {
		t.Logf("Running test case %s", testname)
		lastIndex := len(test.sequence) - 1
		for i, pa := range test.sequence {
			assertString := fmt.Sprintf("test %s sequence %d",
				testname, i)
			res, err := h.Print(pa.format, pa.args...)
			if i == lastIndex {
				assert.Equal(t, test.expected, res, assertString)
				if test.expected {
					assert.Nil(t, err, assertString)
				} else {
					assert.NotNil(t, err, assertString)
				}
			} else {
				assert.Equal(t, true, res, assertString)
				assert.Nil(t, err, assertString)
			}
		}
		h.Flush()
	}
}

func TestPrintIfSpaceFile(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "diag", 0)
	outfile := os.Stdout
	stateFile, err := os.CreateTemp("/tmp", "diag.out")
	if err != nil {
		log.Fatal(err)
	}
	defer stateFile.Close()
	defer os.Remove(stateFile.Name())
	stateFilename := stateFile.Name()
	maxRows := 3 + 1 // Add one for any Exceeded output
	maxColumns := 10

	type printArg struct {
		format string
		args   []interface{}
	}
	type printArgs struct {
		sequence  []printArg
		expected  bool // Checked on last call only
		lineCount int
	}
	printTests := map[string]printArgs{
		"threeFits": {
			sequence: []printArg{
				{format: string9n},
				{format: string9a},
				{format: string9A},
			},
			expected:  true,
			lineCount: 3,
		},
		"threeFitsExact": {
			sequence: []printArg{
				{format: string10n},
				{format: string10a},
				{format: string10A},
			},
			expected:  true,
			lineCount: 3,
		},
		"threeFitsExactPlus": {
			sequence: []printArg{
				{format: string10n},
				{format: string10a},
				{format: string11A},
			},
			expected:  false,
			lineCount: 4,
		},
		"fourFail": {
			sequence: []printArg{
				{format: string9n},
				{format: string9a},
				{format: string9A},
				{format: string9n},
			},
			expected:  false,
			lineCount: 5,
		},
		"wrapThree": {
			sequence: []printArg{
				{format: string11n},
				{format: string9a},
				{format: string9A},
			},
			expected:  false,
			lineCount: 4,
		},
		"leadingTwo": {
			sequence: []printArg{
				{format: leading9},
				{format: string9n},
			},
			expected:  true,
			lineCount: 3,
		},
		"leadingThree": {
			sequence: []printArg{
				{format: leading9},
				{format: string9A},
				{format: string9a},
			},
			expected:  false,
			lineCount: 5,
		},
		"trailingTwo": {
			sequence: []printArg{
				{format: string9n},
				{format: trailing9},
			},
			expected:  true,
			lineCount: 3,
		},
		"trailingThree": {
			sequence: []printArg{
				{format: string9n},
				{format: string9a},
				{format: trailing9},
			},
			expected:  false,
			lineCount: 5,
		},
		"fmtTwo": {
			sequence: []printArg{
				{
					format: fmt2,
					args:   []interface{}{string11, string11},
				},
			},
			expected:  true,
			lineCount: 1,
		},
		"fmtThree": {
			sequence: []printArg{
				{
					format: fmt3,
					args:   []interface{}{string9, string9, string10},
				},
			},
			expected:  true,
			lineCount: 1,
		},
		"fmtThreePlus": {
			sequence: []printArg{
				{
					format: fmt3,
					args:   []interface{}{string9, string10, string10},
				},
			},
			expected:  false,
			lineCount: 2,
		},
		"fmtwrap": {
			sequence: []printArg{
				{
					format: fmt2,
					args:   []interface{}{string10, string9a},
				},
			},
			expected:  true,
			lineCount: 2,
		},
		"longest": {
			sequence: []printArg{
				{format: longest},
			},
			expected:  true,
			lineCount: 1,
		},
		"too long": {
			sequence: []printArg{
				{format: toolong},
			},
			expected:  false,
			lineCount: 1,
		},
	}

	h := PrintIfSpaceInit(outfile, stateFilename,
		maxRows, maxColumns)
	for testname, test := range printTests {
		t.Logf("Running test case %s", testname)
		lastIndex := len(test.sequence) - 1
		for i, pa := range test.sequence {
			assertString := fmt.Sprintf("test %s sequence %d",
				testname, i)
			res, err := h.Print(pa.format, pa.args...)
			if i == lastIndex {
				assert.Equal(t, test.expected, res, assertString)
				if test.expected {
					assert.Nil(t, err, assertString)
				} else {
					assert.NotNil(t, err, assertString)
				}
			} else {
				assert.Equal(t, true, res, assertString)
				assert.Nil(t, err, assertString)
			}
		}
		h.Flush()
		lineCount := linesInFile(stateFilename)
		assert.Equal(t, test.lineCount, lineCount, testname)
	}
}

func linesInFile(filename string) (lineCount int) {
	file, err := os.Open(filename)
	if err != nil {
		log.Error(err)
		lineCount = -1
		return
	}
	fileScanner := bufio.NewScanner(file)
	lineCount = 0
	for fileScanner.Scan() {
		lineCount++
	}
	return
}
