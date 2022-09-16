// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage Xen guest domains based on the subscribed collection of DomainConfig
// and publish the result in a collection of DomainStatus structs.
// We run a separate go routine for each domU to be able to boot and halt
// them concurrently and also pick up their state periodically.

package domainmgr

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestFetchEnvVariablesFromCloudInit(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "domainmgr", 0)
	type fetchEnvVar struct {
		cloudInitStr string
		expectOutput map[string]string
	}
	// testStrings are base 64 encoded strings which will contain
	// environment variables which user will pass in custom config
	// template in the manifest.
	// testString1 contains FOO=BAR environment variables which will
	// be set inside container.
	testString1 := "Rk9PPUJBUg=="
	// testString2 contains SQL_ROOT_PASSWORD=$omeR&NdomPa$$word environment variables which will
	// be set inside container.
	testString2 := "U1FMX1JPT1RfUEFTU1dPUkQ9JG9tZVImTmRvbVBhJCR3b3Jk"
	// testString3 contains PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
	// environment variables which will be set inside container.
	testString3 := "UEFUSD0vdXNyL2xvY2FsL3NiaW46L3Vzci9sb2NhbC9iaW46L3Vzci9zYmluOi91c3IvYmluOi9zYmluOi9iaW4="
	// testString4 contains FOO=1 2 (with space in between)
	// environment variables which will be set inside container.
	testString4 := "Rk9PPTEgMg=="
	// testString5 contains
	// FOO1=BAR1
	// FOO2=		[Without value]
	// FOO3			[Only key without delimiter]
	// FOO4=BAR4
	// environment variables which will be set inside container.
	testString5 := "Rk9PMT1CQVIxCkZPTzI9CkZPTzMKRk9PND1CQVI0"
	testFetchEnvVar := map[string]fetchEnvVar{
		"Test env var 1": {
			cloudInitStr: testString1,
			expectOutput: map[string]string{
				"FOO": "BAR",
			},
		},
		"Test env var 2": {
			cloudInitStr: testString2,
			expectOutput: map[string]string{
				"SQL_ROOT_PASSWORD": "$omeR&NdomPa$$word",
			},
		},
		"Test env var 3": {
			cloudInitStr: testString3,
			expectOutput: map[string]string{
				"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			},
		},
		"Test env var 4": {
			cloudInitStr: testString4,
			expectOutput: map[string]string{
				"FOO": "1 2",
			},
		},
		"Negative test env var 5": {
			cloudInitStr: testString5,
		},
	}
	for testname, test := range testFetchEnvVar {
		t.Logf("Running test case %s", testname)
		envMap, err := decodeAndParseEnvVariablesFromCloudInit(test.cloudInitStr)
		switch testname {
		case "Negative test env var 5":
			if err == nil {
				t.Errorf("Fetching env variable from cloud init passed, expecting it to be failed.")
			}
		default:
			if err != nil {
				t.Errorf("Fetching env variable from cloud init failed: %v", err)
			}
			if !reflect.DeepEqual(envMap, test.expectOutput) {
				t.Errorf("Env map ( %v ) != Expected value ( %v )", envMap, test.expectOutput)
			}
		}
	}
}

func decodeAndParseEnvVariablesFromCloudInit(ciStr string) (map[string]string, error) {
	ud, err := base64.StdEncoding.DecodeString(ciStr)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed %s", err)
	}

	return parseEnvVariablesFromCloudInit(string(ud))
}

// Definitions of various cloud-init multi-part messages

var ciGood = `Content-Type: multipart/mixed; boundary="===============dZOZMyOGZ9KiSApI=="
MIME-Version: 1.0

--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="commands.txt"

echo "Hello World!"



--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="empty.txt"

--===============dZOZMyOGZ9KiSApI==--
`

var ciNoct = `MIME-Version: 1.0

--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="commands.txt"

echo "Hello World!"



--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="empty.txt"

--===============dZOZMyOGZ9KiSApI==--
`

var ciNoboundary = `Content-Type: multipart/mixed"
MIME-Version: 1.0

--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="commands.txt"

echo "Hello World!"



--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="empty.txt"

--===============dZOZMyOGZ9KiSApI==--
`

var ciNotmultipart = `Content-Type: text/mixed; boundary="===============dZOZMyOGZ9KiSApI=="
MIME-Version: 1.0

--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="commands.txt"

echo "Hello World!"



--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="empty.txt"

--===============dZOZMyOGZ9KiSApI==--
`

var ciNofile = `Content-Type: multipart/mixed; boundary="===============dZOZMyOGZ9KiSApI=="
MIME-Version: 1.0

--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment"

echo "Hello World!"



--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="empty.txt"

--===============dZOZMyOGZ9KiSApI==--
`

var ciNocd = `Content-Type: multipart/mixed; boundary="===============dZOZMyOGZ9KiSApI=="
MIME-Version: 1.0

--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="commands.txt"

echo "Hello World!"



--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

--===============dZOZMyOGZ9KiSApI==--
`

var ciSubdirs = `Content-Type: multipart/mixed; boundary="===============dZOZMyOGZ9KiSApI=="
MIME-Version: 1.0

--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="a/b/commands.txt"

echo "Hello World!"



--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="a/c/../../empty.txt"

--===============dZOZMyOGZ9KiSApI==--
`

var ciEscape = `Content-Type: multipart/mixed; boundary="===============dZOZMyOGZ9KiSApI=="
MIME-Version: 1.0

--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="a/../../commands.txt"

echo "Hello World!"



--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="a/c/../../empty.txt"

--===============dZOZMyOGZ9KiSApI==--
`

var ciTruncated = `Content-Type: multipart/mixed; boundary="===============dZOZMyOGZ9KiSApI=="
MIME-Version: 1.0

--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="commands.txt"

echo "Hello World!"



--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="empty.txt"

`

var ciTruncatedOne = `Content-Type: multipart/mixed; boundary="===============dZOZMyOGZ9KiSApI=="
MIME-Version: 1.0

--===============dZOZMyOGZ9KiSApI==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="commands.txt"

echo "Hello World!"



--===============dZOZMyOGZ9KiSApI==
`

var ciTruncatedZero = `Content-Type: multipart/mixed; boundary="===============dZOZMyOGZ9KiSApI=="
MIME-Version: 1.0

`

func TestHandleMimeMultipart(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "domainmgr", 0)
	testMatrix := map[string]struct {
		ciStr           string
		expectMultipart bool
		expectFail      bool
		expectFiles     []string
		expectDirs      []string
	}{
		"Test empty": {
			ciStr:           "",
			expectMultipart: false,
			expectFail:      false,
		},
		"Test no Content-Type": {
			ciStr:           ciNoct,
			expectMultipart: false,
			expectFail:      false,
		},
		"Test no boundary": {
			ciStr:           ciNoboundary,
			expectMultipart: false,
			expectFail:      false,
		},
		"Test not Content-Type multipart": {
			ciStr:           ciNotmultipart,
			expectMultipart: false,
			expectFail:      false,
		},
		"Test no filename": {
			ciStr:           ciNofile,
			expectMultipart: true,
			expectFail:      true,
		},
		"Test no Content-Disposition": {
			ciStr:           ciNocd,
			expectMultipart: true,
			expectFail:      true,
			expectFiles:     []string{"/commands.txt"},
		},
		"Test good": {
			ciStr:           ciGood,
			expectMultipart: true,
			expectFail:      false,
			expectFiles:     []string{"/commands.txt", "/empty.txt"},
		},
		"Test subdirs": {
			ciStr:           ciSubdirs,
			expectMultipart: true,
			expectFail:      false,
			expectFiles:     []string{"/a/b/commands.txt", "/empty.txt"},
			expectDirs:      []string{"/a", "/a/b"},
		},
		"Test escape": {
			ciStr:           ciEscape,
			expectMultipart: true,
			expectFail:      true,
		},
		"Test truncated": {
			ciStr:           ciTruncated,
			expectMultipart: true,
			expectFail:      true,
			expectFiles:     []string{"/commands.txt", "/empty.txt"},
		},
		"Test truncated one": {
			ciStr:           ciTruncatedOne,
			expectMultipart: true,
			expectFail:      false,
			expectFiles:     []string{"/commands.txt"},
		},
		"Test truncated zero": {
			ciStr:           ciTruncatedZero,
			expectMultipart: true,
			expectFail:      true,
		},
	}
	dir, err := ioutil.TempDir("", "domainmgr_test")
	assert.Nil(t, err)
	if err != nil {
		return
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		mydir := dir + "/" + testname
		err = os.Mkdir(mydir, 0700)
		assert.Nil(t, err)
		if err != nil {
			continue
		}
		ok, err := handleMimeMultipart(mydir, test.ciStr, true)
		assert.Equal(t, test.expectMultipart, ok)
		if test.expectFail {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
		var files []string
		var dirs []string
		err = filepath.Walk(mydir, func(path string, info os.FileInfo, e error) error {
			if e != nil {
				return e
			}
			// Update files and dirs except top level dir
			filename := strings.TrimPrefix(path, mydir)
			if info.Mode().IsRegular() {
				files = append(files, filename)
			} else if info.Mode().IsDir() && filename != "" {
				dirs = append(dirs, filename)
			}
			return nil
		})
		assert.Nil(t, err)
		if err != nil {
			continue
		}
		assert.Equal(t, len(test.expectFiles), len(files))
		if len(test.expectFiles) == len(files) {
			for i := range files {
				assert.Equal(t, test.expectFiles[i], files[i])
			}
		}
		assert.Equal(t, len(test.expectDirs), len(dirs))
		if len(test.expectDirs) == len(dirs) {
			for i := range dirs {
				assert.Equal(t, test.expectDirs[i], dirs[i])
			}
		}
	}
	os.RemoveAll(dir)
}
