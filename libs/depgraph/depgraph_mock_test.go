// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package depgraph_test

import (
	"fmt"
	"reflect"

	"github.com/lf-edge/eve/libs/depgraph"
)

type mockItemAttrs struct {
	intAttr  int
	strAttr  string
	boolAttr bool
}

type mockItem struct {
	name     string
	itemType string
	attrs    mockItemAttrs
	deps     []depgraph.Dependency
}

type mockItemState struct {
	isCreated    bool
	inTransition bool
	withErr      error
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
	return reflect.DeepEqual(m.attrs, m2.(mockItem).attrs) &&
		reflect.DeepEqual(m.deps, m2.(mockItem).deps)
}

func (m mockItem) External() bool {
	return false
}

func (m mockItem) String() string {
	return fmt.Sprintf("item type:%s name:%s with attrs: %v",
		m.Type(), m.Name(), m.attrs)
}

func (m mockItem) Dependencies() []depgraph.Dependency {
	return m.deps
}

func (m mockItemState) String() string {
	return ""
}

func (m mockItemState) IsCreated() bool {
	return m.isCreated
}

func (m mockItemState) WithError() error {
	return m.withErr
}

func (m mockItemState) InTransition() bool {
	return m.inTransition
}
