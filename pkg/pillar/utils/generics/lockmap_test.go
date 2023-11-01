// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package generics_test

import (
	"sync"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	. "github.com/onsi/gomega"
)

func TestLockedMap(t *testing.T) {
	t.Parallel()

	g := NewGomegaWithT(t)

	lm := generics.NewLockedMap[int, string]()

	lm.Store(42, "bazinga")

	got, ok := lm.Load(42)
	g.Expect(ok).To(BeEquivalentTo(true))
	g.Expect(got).To(BeEquivalentTo("bazinga"))

	lm.Delete(42)
	got, ok = lm.Load(42)
	// in case value does not exist, underlying
	// map will return default-initialized value for
	// type V of LockedMap in this case it will be
	// empty string
	g.Expect(got).To(BeEquivalentTo(""))
	g.Expect(ok).To(BeEquivalentTo(false))
}

func TestLockedMapAsyncWriteRead(t *testing.T) {
	t.Parallel()

	g := NewGomegaWithT(t)

	data := map[int]string{
		42:    "bazinga",
		51:    "anotherpayload",
		581:   "test",
		423:   "another test",
		5103:  "Another text",
		10213: "Some more text",
	}

	lm := generics.NewLockedMap[int, string]()

	wg := sync.WaitGroup{}

	for k, v := range data {
		wg.Add(1)
		keyCopy, valueCopy := k, v
		go func() {
			lm.Store(keyCopy, valueCopy)
			// check that value is stored
			got, ok := lm.Load(keyCopy)
			g.Expect(ok).To(BeEquivalentTo(true))
			g.Expect(got).To(BeEquivalentTo(valueCopy))
			wg.Done()
		}()
	}

	wg.Wait()

	// check that all values are present
	for k, v := range data {
		got, ok := lm.Load(k)
		g.Expect(ok).To(BeEquivalentTo(true))
		g.Expect(got).To(BeEquivalentTo(v))
	}
}
