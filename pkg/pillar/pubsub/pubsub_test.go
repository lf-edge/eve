package pubsub

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type Item struct {
	aString string
}

var (
	item = Item{
		aString: "aString",
	}
)

type EmptyDriver struct{}

func (e *EmptyDriver) Publisher(global bool, name, topic string, persistent bool, updaterList *Updaters, restarted Restarted, differ Differ) (DriverPublisher, error) {
	return &EmptyDriverPublisher{}, nil
}
func (e *EmptyDriver) Subscriber(global bool, name, topic string, persistent bool, C chan Change) (DriverSubscriber, error) {
	return &EmptyDriverSubscriber{}, nil
}

type EmptyDriverPublisher struct{}

func (e *EmptyDriverPublisher) Start() error {
	return nil
}
func (e *EmptyDriverPublisher) Load() (map[string]interface{}, bool, error) {
	return make(map[string]interface{}), false, nil
}
func (e *EmptyDriverPublisher) Publish(key string, item interface{}) error {
	return nil
}
func (e *EmptyDriverPublisher) Unpublish(key string) error {
	return nil
}
func (e *EmptyDriverPublisher) Restart(restarted bool) error {
	return nil
}

type EmptyDriverSubscriber struct{}

func (e *EmptyDriverSubscriber) Start() error {
	return nil
}
func (e *EmptyDriverSubscriber) DefaultName() string {
	return "empty"
}

func TestHandleModify(t *testing.T) {
	ps := New(&EmptyDriver{})
	sub, err := ps.Subscribe("agentName", item, false, &item)
	if err != nil {
		t.Fatalf("unable to subscribe: %v", err)
	}
	sub.agentScope = "agentScope"
	sub.topic = "topic"
	created := false
	modified := false
	subCreateHandler := func(ctxArg interface{}, key string, status interface{}) {
		created = true
	}
	subModifyHandler := func(ctxArg interface{}, key string, status interface{}) {
		modified = true
	}

	testMatrix := map[string]struct {
		ctxArg         *Subscription
		key            string
		item           interface{}
		modifyHandler  SubHandler
		createHandler  SubHandler
		expectedCreate bool
		expectedModify bool
	}{
		"Modify Handler is nil": {
			ctxArg:         &sub,
			key:            "key_0",
			item:           item,
			modifyHandler:  nil,
			createHandler:  subCreateHandler,
			expectedCreate: true,
			expectedModify: false,
		},
		"Create Handler is nil": {
			ctxArg:         &sub,
			key:            "key_1",
			item:           item,
			modifyHandler:  subModifyHandler,
			createHandler:  nil,
			expectedCreate: false,
			expectedModify: true,
		},
		"Create Handler and Modify Handler are nil": {
			ctxArg:         &sub,
			key:            "key_2",
			item:           item,
			modifyHandler:  nil,
			createHandler:  nil,
			expectedCreate: false,
			expectedModify: false,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		test.ctxArg.CreateHandler = test.createHandler
		test.ctxArg.ModifyHandler = test.modifyHandler
		handleModify(test.ctxArg, test.key, test.item)
		// Make sure both weren't called
		assert.Equal(t, created, test.expectedCreate)
		assert.Equal(t, modified, test.expectedModify)
		// Reset created and modified to false for next test
		created = false
		modified = false
	}
}
