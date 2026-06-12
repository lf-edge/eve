// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestAnalyzeMismatch(t *testing.T) {
	result, err := analyze([]string{"testdata/mismatch"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.errors) != 1 {
		t.Fatalf("expected exactly one error, got %v", result.errors)
	}
	if !strings.Contains(result.errors[0], "pubagent/Foo") {
		t.Errorf("unexpected error message: %s", result.errors[0])
	}
}

func TestAnalyzeMatched(t *testing.T) {
	result, err := analyze([]string{"testdata/ok"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.errors)
	}
}

func TestListNonPersistentPublications(t *testing.T) {
	// testdata/mismatch publishes pubagent/Foo non-persistently, so it is
	// listed; testdata/ok publishes it persistently, so the list is empty.
	result, err := analyze([]string{"testdata/mismatch"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.nonPersistentPublications) != 1 ||
		result.nonPersistentPublications[0] != "pubagent/Foo" {
		t.Fatalf("expected [pubagent/Foo], got %v", result.nonPersistentPublications)
	}

	result, err = analyze([]string{"testdata/ok"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.nonPersistentPublications) != 0 {
		t.Fatalf("expected no non-persistent publications, got %v",
			result.nonPersistentPublications)
	}
}
