// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/libs/reconciler"
)

// Mock asynchronous operations take 3 seconds to complete.
const asyncOpDuration = 3 * time.Second

type mockItemAttrs struct {
	intAttr  int
	strAttr  string
	boolAttr bool
}

type mockItem struct {
	name            string
	itemType        string
	isExternal      bool
	staticAttrs     mockItemAttrs // change of these requires purge
	modifiableAttrs mockItemAttrs // can be changed by Modify
	failToCreate    bool          // enable to simulate failed Create/Modify
	failToDelete    bool          // enable to simulate failed Delete
	asyncCreate     bool          // Create/Modify item asynchronously
	asyncDelete     bool          // Delete item asynchronously
	deps            []depgraph.Dependency
}

type mockConfigurator struct {
	itemType string
}

func (m mockItem) Name() string {
	return m.name
}

func (m mockItem) Label() string {
	return m.name
}

func (m mockItem) Type() string {
	return m.itemType
}

func (m mockItem) Equal(m2 depgraph.Item) bool {
	return reflect.DeepEqual(m.modifiableAttrs, m2.(mockItem).modifiableAttrs) &&
		reflect.DeepEqual(m.staticAttrs, m2.(mockItem).staticAttrs) &&
		reflect.DeepEqual(m.deps, m2.(mockItem).deps)
}

func (m mockItem) External() bool {
	return m.isExternal
}

func (m mockItem) String() string {
	return fmt.Sprintf("item %s with attrs: %v; %v",
		m.name, m.modifiableAttrs, m.staticAttrs)
}

func (m mockItem) Dependencies() []depgraph.Dependency {
	return m.deps
}

func (m *mockConfigurator) Create(ctx context.Context, item depgraph.Item) (injectedErr error) {
	mItem, ok := item.(mockItem)
	if !ok {
		panic("mockConfigurator only works with mockItem")
	}
	if item.Type() != m.itemType {
		panic("DepGraph called wrong Configurator")
	}
	if item.External() {
		panic("external item should not have configurator associated")
	}
	if mItem.failToCreate {
		injectedErr = errors.New("failed to create")
	}
	if mItem.asyncCreate {
		done := reconciler.ContinueInBackground(ctx)
		go func(injectedErr error) {
			select {
			case <-time.After(asyncOpDuration):
				break
			case <-ctx.Done():
				injectedErr = errors.New("failed to complete")
			}
			done(injectedErr)
		}(injectedErr)
		return nil
	}
	return injectedErr
}

func (m *mockConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (injectedErr error) {
	if oldItem.Name() != newItem.Name() {
		panic("Modify called between different items")
	}
	if newItem.Type() != m.itemType {
		panic("DepGraph called wrong Configurator")
	}
	_, ok := oldItem.(mockItem)
	if !ok {
		panic("mockConfigurator only works with mockItem")
	}
	mNewItem, ok := newItem.(mockItem)
	if !ok {
		panic("mockConfigurator only works with mockItem")
	}
	if oldItem.Equal(newItem) {
		panic("Modify called for item which has not changed")
	}
	if newItem.External() {
		panic("external item should not have configurator associated")
	}
	if mNewItem.failToCreate {
		injectedErr = errors.New("failed to modify")
	}
	if mNewItem.asyncCreate {
		done := reconciler.ContinueInBackground(ctx)
		go func(injectedErr error) {
			select {
			case <-time.After(asyncOpDuration):
				break
			case <-ctx.Done():
				injectedErr = errors.New("failed to complete")
			}
			done(injectedErr)
		}(injectedErr)
		return nil
	}
	return injectedErr
}

func (m *mockConfigurator) Delete(ctx context.Context, item depgraph.Item) (injectedErr error) {
	mItem, ok := item.(mockItem)
	if !ok {
		panic("mockConfigurator only works with mockItem")
	}
	if item.Type() != m.itemType {
		panic("DepGraph called wrong Configurator")
	}
	if item.External() {
		panic("external item should not have configurator associated")
	}
	if mItem.failToDelete {
		injectedErr = errors.New("failed to delete")
	}
	if mItem.asyncDelete {
		done := reconciler.ContinueInBackground(ctx)
		go func(injectedErr error) {
			select {
			case <-time.After(asyncOpDuration):
				break
			case <-ctx.Done():
				injectedErr = errors.New("failed to complete")
			}
			done(injectedErr)
		}(injectedErr)
		return nil
	}
	return injectedErr
}

func (m *mockConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	if newItem.Type() != m.itemType {
		panic("DepGraph called wrong Configurator")
	}
	mOldItem, ok := oldItem.(mockItem)
	if !ok {
		panic("mockConfigurator only works with mockItem")
	}
	mNewItem, ok := newItem.(mockItem)
	if !ok {
		panic("mockConfigurator only works with mockItem")
	}
	return !reflect.DeepEqual(mOldItem.staticAttrs, mNewItem.staticAttrs)
}
