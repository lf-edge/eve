// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

type valueItem struct {
	Name string
	Tags map[string]string
}

func newValuePublication(t *testing.T) *PublicationImpl {
	t.Helper()
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	pub, err := New(NewMemoryDriver(), logger, log).NewPublication(
		PublicationOptions{AgentName: "test", TopicType: valueItem{}})
	if err != nil {
		t.Fatal(err)
	}
	return pub.(*PublicationImpl)
}

func mustPublish(t *testing.T, pub *PublicationImpl, key string, item valueItem) {
	t.Helper()
	if err := pub.Publish(key, item); err != nil {
		t.Fatal(err)
	}
}

// checkDiffs checks that DetermineDiffs returns the deleted keys, then the
// changed ones, each in any order.
func checkDiffs(t *testing.T, pub *PublicationImpl, local LocalCollection,
	deleted, changed []string) {
	t.Helper()
	got := pub.DetermineDiffs(local)
	same := func(a, b []string) bool {
		a, b = append([]string{}, a...), append([]string{}, b...)
		sort.Strings(a)
		sort.Strings(b)
		return strings.Join(a, " ") == strings.Join(b, " ")
	}
	if len(got) != len(deleted)+len(changed) ||
		!same(got[:len(deleted)], deleted) || !same(got[len(deleted):], changed) {
		t.Fatalf("DetermineDiffs returned %v, expected %v deleted then %v",
			got, deleted, changed)
	}
}

// TestDetermineDiffsSharesValues checks that every subscriber connection
// is handed the same Value of a key, the one Publish made, and that a key
// is sent again only when Publish changed it.
func TestDetermineDiffsSharesValues(t *testing.T) {
	pub := newValuePublication(t)
	mustPublish(t, pub, "a", valueItem{Name: "a"})
	mustPublish(t, pub, "b", valueItem{Name: "b"})

	first, second := LocalCollection{}, LocalCollection{}
	checkDiffs(t, pub, first, nil, []string{"a", "b"})
	checkDiffs(t, pub, second, nil, []string{"a", "b"})
	for key, value := range first {
		if second[key] != value {
			t.Errorf("key %s: the two collections hold different values", key)
		}
	}
	checkDiffs(t, pub, first, nil, nil)

	// The same JSON again is no change.
	mustPublish(t, pub, "a", valueItem{Name: "a"})
	checkDiffs(t, pub, first, nil, nil)

	mustPublish(t, pub, "a", valueItem{Name: "a2"})
	checkDiffs(t, pub, first, nil, []string{"a"})
	if string(first["a"].JSON) != `{"Name":"a2","Tags":null}` {
		t.Errorf("a is %s", first["a"].JSON)
	}

	// Deleted keys come first.
	if err := pub.Unpublish("b"); err != nil {
		t.Fatal(err)
	}
	mustPublish(t, pub, "c", valueItem{Name: "c"})
	checkDiffs(t, pub, first, []string{"b"}, []string{"c"})
	if _, ok := first["b"]; ok {
		t.Error("the deleted key is still in the collection")
	}
	checkDiffs(t, pub, second, []string{"b"}, []string{"a", "c"})
}

// looseItem is equal to another of the same Name, whatever its Note.
type looseItem struct {
	Name string
	Note string
}

func (l looseItem) Equal(l2 looseItem) bool {
	return l.Name == l2.Name
}

// TestPublishHonoursEqual checks that an item which marshals to other JSON
// but is equal by the Equal method of its type is unchanged, as before.
func TestPublishHonoursEqual(t *testing.T) {
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	p, err := New(NewMemoryDriver(), logger, log).NewPublication(
		PublicationOptions{AgentName: "test", TopicType: looseItem{}})
	if err != nil {
		t.Fatal(err)
	}
	pub := p.(*PublicationImpl)
	local := LocalCollection{}
	for _, step := range []struct {
		item    looseItem
		changed []string
	}{
		{looseItem{"a", "x"}, []string{"k"}},
		{looseItem{"a", "y"}, nil},
		{looseItem{"b", "y"}, []string{"k"}},
	} {
		if err := pub.Publish("k", step.item); err != nil {
			t.Fatal(err)
		}
		checkDiffs(t, pub, local, nil, step.changed)
	}
	if got, _ := pub.Get("k"); got.(looseItem) != (looseItem{"b", "y"}) {
		t.Errorf("Get returned %v", got)
	}
}

// TestPublicationCopies checks that a publication keeps a copy of what is
// published, and hands out copies, decoded from the JSON it keeps.
func TestPublicationCopies(t *testing.T) {
	pub := newValuePublication(t)
	item := valueItem{Name: "a", Tags: map[string]string{"k": "v"}}
	mustPublish(t, pub, "a", item)
	item.Tags["k"] = "changed by the publisher"

	got, err := pub.Get("a")
	if err != nil {
		t.Fatal(err)
	}
	if v := got.(valueItem).Tags["k"]; v != "v" {
		t.Fatalf("Get returned %q, published %q", v, "v")
	}
	got.(valueItem).Tags["k"] = "changed by the caller of Get"
	pub.GetAll()["a"].(valueItem).Tags["k"] = "changed by the caller of GetAll"

	all := pub.GetAll()
	if len(all) != 1 || all["a"].(valueItem).Tags["k"] != "v" {
		t.Fatalf("GetAll returned %v", all)
	}
	pub.Iterate(func(key string, val interface{}) bool {
		if key != "a" || val.(valueItem).Tags["k"] != "v" {
			t.Errorf("Iterate handed out %s: %v", key, val)
		}
		return true
	})
}

// TestHandlerGetsCopy checks that what a handler changes in the item it is
// given does not change the item of the subscription.
func TestHandlerGetsCopy(t *testing.T) {
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	ps := New(&EmptyDriver{}, logger, log)
	var calls int
	change := func(_ interface{}, _ string, status interface{}) {
		calls++
		status.(valueItem).Tags["k"] = "changed by the handler"
	}
	sub, err := ps.NewSubscription(SubscriptionOptions{
		AgentName: "test", TopicImpl: valueItem{},
		CreateHandler: change,
		ModifyHandler: func(ctx interface{}, key string, status, _ interface{}) {
			change(ctx, key, status)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	impl := sub.(*SubscriptionImpl)
	handleModify(impl, "a", []byte(`{"Name":"a","Tags":{"k":"v"}}`))
	handleModify(impl, "a", []byte(`{"Name":"a","Tags":{"k":"v"}}`))
	handleModify(impl, "a", []byte(`{"Name":"a2","Tags":{"k":"v"}}`))
	if calls != 2 {
		t.Errorf("the handlers were called %d times, expected 2", calls)
	}
	got, err := sub.Get("a")
	if err != nil {
		t.Fatal(err)
	}
	if item := got.(valueItem); item.Name != "a2" || item.Tags["k"] != "v" {
		t.Errorf("the subscription holds %v", item)
	}
}

// countedItem counts how often it is decoded.
type countedItem struct {
	Name string
}

var countedDecodes int

func (c *countedItem) UnmarshalJSON(b []byte) error {
	countedDecodes++
	type plain countedItem
	return json.Unmarshal(b, (*plain)(c))
}

// TestIdenticalNotDecoded checks that a persistent subscription, until it
// is synchronized, does not decode the JSON it holds an item for already,
// nor call a handler for it; that afterwards it decodes and compares as
// before; and that it never calls a handler for JSON which decodes to the
// item it holds.
func TestIdenticalNotDecoded(t *testing.T) {
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	var calls int
	sub, err := New(&EmptyDriver{}, logger, log).NewSubscription(SubscriptionOptions{
		AgentName: "testsum", TopicImpl: countedItem{}, Persistent: true,
		CreateHandler: func(interface{}, string, interface{}) { calls++ },
		ModifyHandler: func(interface{}, string, interface{}, interface{}) { calls++ },
		DeleteHandler: func(interface{}, string, interface{}) { calls++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	impl := sub.(*SubscriptionImpl)
	unchanged := &SubscriptionStats("testsum/countedItem").Unchanged
	for _, step := range []struct {
		json           string
		delete, sync   bool
		decodes, calls int
		unchanged      int64
	}{
		{json: `{"Name":"a"}`, decodes: 2, calls: 1},                  // decoded, and copied for the handler
		{json: `{"Name":"a"}`, unchanged: 1},                          // the same JSON
		{json: `{"Name":"a", "Unknown":1}`, decodes: 1, unchanged: 1}, // other JSON, the same item
		{json: `{"Name":"a", "Unknown":1}`, unchanged: 1},
		{json: `{"Name":"b"}`, decodes: 2, calls: 1},
		{delete: true, calls: 1},
		{json: `{"Name":"b"}`, decodes: 2, calls: 1}, // created again
		{sync: true},
		{json: `{"Name":"b"}`, decodes: 1, unchanged: 1}, // synchronized: decoded and compared
		{json: `{"Name":"c"}`, decodes: 2, calls: 1},
	} {
		decodes, before, unchangedBefore := countedDecodes, calls, unchanged.Load()
		switch {
		case step.sync:
			handleSynchronized(impl, true)
			if impl.sums != nil {
				t.Error("the sums are kept after the subscription is synchronized")
			}
		case step.delete:
			handleDelete(impl, "key")
		default:
			handleModify(impl, "key", []byte(step.json))
		}
		if d := countedDecodes - decodes; d != step.decodes {
			t.Errorf("%s: decoded %d times, expected %d", step.json, d, step.decodes)
		}
		if c := calls - before; c != step.calls {
			t.Errorf("%s: %d handler calls, expected %d", step.json, c, step.calls)
		}
		if u := unchanged.Load() - unchangedBefore; u != step.unchanged {
			t.Errorf("%s: counted %d unchanged, expected %d", step.json, u, step.unchanged)
		}
	}
}
