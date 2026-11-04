// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

// Tag labels a test or a test suite for tools that schedule or filter them.
type Tag string

const (
	// TagHeavyTest marks a test or suite that needs a powerful host: one focused
	// on EVE-k, or one that takes more than about 90 minutes on a strong host.
	// CI schedules whole suites, so a suite with this tag is run only on the
	// strong runners, never on the weak ones.
	TagHeavyTest Tag = "heavy"
)

// WithTags attaches tags to the test or suite whose Init call it is passed to.
// It has no effect at run time: list-tests reads the tags statically from the
// source, shows them, and hands the ones of suites to CI. Pass constants from
// this package directly, e.g.
//
//	evetest.Init(test, evetest.WithTags(evetest.TagHeavyTest))
func WithTags(tags ...Tag) InitOption {
	return func(o *initOptions) { o.tags = append(o.tags, tags...) }
}
