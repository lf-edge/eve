// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage Xen guest domains based on the subscribed collection of DomainConfig
// and publish the result in a collection of DomainStatus structs.
// We run a separate go routine for each domU to be able to boot and halt
// them concurrently and also pick up their state periodically.

package domainmgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	"reflect"
	"testing"
)

func TestFetchEnvVariablesFromCloudInit(t *testing.T) {
	type fetchEnvVar struct {
		config       types.DomainConfig
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
	// environment variables which wil be set inside container.
	testString3 := "UEFUSD0vdXNyL2xvY2FsL3NiaW46L3Vzci9sb2NhbC9iaW46L3Vzci9zYmluOi91c3IvYmluOi9zYmluOi9iaW4="
	// testString4 contains FOO=1 2 (with space in between)
	// environment variables which wil be set inside container.
	testString4 := "Rk9PPTEgMg=="
	// testString5 contains
	// FOO1=BAR1
	// FOO2=		[Without value]
	// FOO3			[Only key without delimiter]
	// FOO4=BAR4
	// environment variables which wil be set inside container.
	testString5 := "Rk9PMT1CQVIxCkZPTzI9CkZPTzMKRk9PND1CQVI0"
	testFetchEnvVar := map[string]fetchEnvVar{
		"Test env var 1": {
			config: types.DomainConfig{
				CloudInitUserData: &testString1,
			},
			expectOutput: map[string]string{
				"FOO": "BAR",
			},
		},
		"Test env var 2": {
			config: types.DomainConfig{
				CloudInitUserData: &testString2,
			},
			expectOutput: map[string]string{
				"SQL_ROOT_PASSWORD": "$omeR&NdomPa$$word",
			},
		},
		"Test env var 3": {
			config: types.DomainConfig{
				CloudInitUserData: &testString3,
			},
			expectOutput: map[string]string{
				"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			},
		},
		"Test env var 4": {
			config: types.DomainConfig{
				CloudInitUserData: &testString4,
			},
			expectOutput: map[string]string{
				"FOO": "1 2",
			},
		},
		"Negative test env var 5": {
			config: types.DomainConfig{
				CloudInitUserData: &testString5,
			},
		},
	}
	for testname, test := range testFetchEnvVar {
		t.Logf("Running test case %s", testname)
		envMap, err := fetchEnvVariablesFromCloudInit(nil, test.config)
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
