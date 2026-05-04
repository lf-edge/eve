package types

import (
	"fmt"
	"testing"

	"github.com/lf-edge/eve-api/go/info"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTriState(t *testing.T) {
	testMatrix := map[string]struct {
		err   error
		ts    TriState
		value string
	}{
		"Value none": {
			err:   nil,
			ts:    TS_NONE,
			value: "none",
		},

		"Value enable": {
			err:   nil,
			ts:    TS_ENABLED,
			value: "enable",
		},
		"Value enabled": {
			err:   nil,
			ts:    TS_ENABLED,
			value: "enabled",
		},
		"Value on": {
			err:   nil,
			ts:    TS_ENABLED,
			value: "on",
		},
		"Value disabled": {
			err:   nil,
			ts:    TS_DISABLED,
			value: "disabled",
		},
		"Value disable": {
			err:   nil,
			ts:    TS_DISABLED,
			value: "disable",
		},
		"Value off": {
			err:   nil,
			ts:    TS_DISABLED,
			value: "off",
		},
		"Value bad-value": {
			err:   fmt.Errorf("Bad value: bad-value"),
			ts:    TS_NONE,
			value: "bad-value",
		},
	}

	for testname, test := range testMatrix {
		t.Logf("Running test %s", testname)
		ts, err := ParseTriState(test.value)
		assert.IsType(t, test.err, err)
		assert.Equal(t, test.ts, ts)
	}
}

func TestFormatTriState(t *testing.T) {
	assert.Equal(t, "none", FormatTriState(TS_NONE))
	assert.Equal(t, "enabled", FormatTriState(TS_ENABLED))
	assert.Equal(t, "disabled", FormatTriState(TS_DISABLED))
}

func TestUuidsToStrings(t *testing.T) {
	id1 := uuid.Must(uuid.NewV4())
	id2 := uuid.Must(uuid.NewV4())
	strs := UuidsToStrings([]uuid.UUID{id1, id2})
	assert.Equal(t, []string{id1.String(), id2.String()}, strs)

	// Empty slice
	assert.Equal(t, []string{}, UuidsToStrings([]uuid.UUID{}))
}

// SwState.String

func TestSwStateString(t *testing.T) {
	cases := []struct {
		state SwState
		want  string
	}{
		{INITIAL, "INITIAL"},
		{RESOLVING_TAG, "RESOLVING_TAG"},
		{RESOLVED_TAG, "RESOLVED_TAG"},
		{DOWNLOADING, "DOWNLOADING"},
		{DOWNLOADED, "DOWNLOADED"},
		{VERIFYING, "VERIFYING"},
		{VERIFIED, "VERIFIED"},
		{LOADING, "LOADING"},
		{LOADED, "LOADED"},
		{CREATING_VOLUME, "CREATING_VOLUME"},
		{CREATED_VOLUME, "CREATED_VOLUME"},
		{INSTALLED, "INSTALLED"},
		{AWAITNETWORKINSTANCE, "AWAITNETWORKINSTANCE"},
		{BOOTING, "BOOTING"},
		{RUNNING, "RUNNING"},
		{PAUSING, "PAUSING"},
		{PAUSED, "PAUSED"},
		{HALTING, "HALTING"},
		{HALTED, "HALTED"},
		{PENDING, "PENDING"},
		{FAILED, "FAILED"},
		{SCHEDULING, "SCHEDULING"},
		{BROKEN, "BROKEN"},
		{START_DELAYED, "START_DELAYED"},
		{REMOTELOADED, "REMOTELOADED"},
		{UNKNOWN, "UNKNOWN"},
		{SwState(99), fmt.Sprintf("Unknown state %d", 99)},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.state.String())
	}
}

// UuidToNum methods

func TestUuidToNumSetGetNumber(t *testing.T) {
	u := &UuidToNum{}
	u.SetNumber(42, "appNum")
	n, typ := u.GetNumber()
	assert.Equal(t, 42, n)
	assert.Equal(t, "appNum", typ)
}

func TestUuidToNumGetTimestamps(t *testing.T) {
	u := &UuidToNum{}
	created, last := u.GetTimestamps()
	assert.True(t, created.IsZero())
	assert.True(t, last.IsZero())
}

func TestUuidToNumReservedOnly(t *testing.T) {
	u := &UuidToNum{InUse: true}
	assert.False(t, u.IsReservedOnly())

	u.SetReservedOnly(true)
	assert.True(t, u.IsReservedOnly())
	assert.False(t, u.InUse)

	u.SetReservedOnly(false)
	assert.False(t, u.IsReservedOnly())
	assert.True(t, u.InUse)
}

func TestUuidToNumNew(t *testing.T) {
	proto := &UuidToNum{}
	key := UuidToNumKey{}
	obj := proto.New(key)
	require.NotNil(t, obj)
	result, ok := obj.(*UuidToNum)
	require.True(t, ok)
	assert.Equal(t, key, result.UuidToNumKey)
	assert.False(t, result.CreateTime.IsZero())
	assert.False(t, result.LastUseTime.IsZero())
}

// AppInterfaceToNum methods

func TestAppInterfaceToNumSetGetNumber(t *testing.T) {
	u := &AppInterfaceToNum{}
	u.SetNumber(7, "bridgeNum")
	n, typ := u.GetNumber()
	assert.Equal(t, 7, n)
	assert.Equal(t, "bridgeNum", typ)
}

func TestAppInterfaceToNumGetTimestamps(t *testing.T) {
	u := &AppInterfaceToNum{}
	created, last := u.GetTimestamps()
	assert.True(t, created.IsZero())
	assert.True(t, last.IsZero())
}

func TestAppInterfaceToNumReservedOnly(t *testing.T) {
	u := &AppInterfaceToNum{InUse: true}
	assert.False(t, u.IsReservedOnly())

	u.SetReservedOnly(true)
	assert.True(t, u.IsReservedOnly())

	u.SetReservedOnly(false)
	assert.False(t, u.IsReservedOnly())
}

func TestAppInterfaceToNumNew(t *testing.T) {
	proto := &AppInterfaceToNum{}
	key := AppInterfaceKey{}
	obj := proto.New(key)
	require.NotNil(t, obj)
	result, ok := obj.(*AppInterfaceToNum)
	require.True(t, ok)
	assert.Equal(t, key, result.AppInterfaceKey)
	assert.False(t, result.CreateTime.IsZero())
}

// UuidToNum.New panic branch — wrong key type
func TestUuidToNumNewWrongKeyType(t *testing.T) {
	proto := &UuidToNum{}
	assert.Panics(t, func() {
		proto.New(AppInterfaceKey{}) // wrong key type → panic
	})
}

// AppInterfaceToNum.New panic branch — wrong key type
func TestAppInterfaceToNumNewWrongKeyType(t *testing.T) {
	proto := &AppInterfaceToNum{}
	assert.Panics(t, func() {
		proto.New(UuidToNumKey{}) // wrong key type → panic
	})
}

// SwState.ZSwState

func TestSwStateZSwState(t *testing.T) {
	cases := []struct {
		state SwState
		want  info.ZSwState
	}{
		{0, 0},
		{INITIAL, info.ZSwState_INITIAL},
		{RESOLVING_TAG, info.ZSwState_RESOLVING_TAG},
		{RESOLVED_TAG, info.ZSwState_RESOLVED_TAG},
		{DOWNLOADING, info.ZSwState_DOWNLOAD_STARTED},
		{DOWNLOADED, info.ZSwState_DOWNLOADED},
		{VERIFYING, info.ZSwState_VERIFYING},
		{VERIFIED, info.ZSwState_VERIFIED},
		{LOADING, info.ZSwState_LOADING},
		// LOADED maps to DELIVERED (TBD per source comment)
		{LOADED, info.ZSwState_DELIVERED},
		{CREATING_VOLUME, info.ZSwState_CREATING_VOLUME},
		{CREATED_VOLUME, info.ZSwState_CREATED_VOLUME},
		{INSTALLED, info.ZSwState_INSTALLED},
		{AWAITNETWORKINSTANCE, info.ZSwState_AWAITNETWORKINSTANCE},
		{BOOTING, info.ZSwState_BOOTING},
		{RUNNING, info.ZSwState_RUNNING},
		// PAUSING maps to RUNNING (controllers don't support PAUSING)
		{PAUSING, info.ZSwState_RUNNING},
		// PAUSED maps to INSTALLED (controllers don't support PAUSED)
		{PAUSED, info.ZSwState_INSTALLED},
		{HALTING, info.ZSwState_HALTING},
		{HALTED, info.ZSwState_HALTED},
		// BROKEN maps to HALTING (EVE actively reaps BROKEN domains)
		{BROKEN, info.ZSwState_HALTING},
		{START_DELAYED, info.ZSwState_START_DELAYED},
		{FAILED, info.ZSwState_ERROR},
		{PENDING, info.ZSwState_PENDING},
		{SCHEDULING, info.ZSwState_SCHEDULING},
		{REMOTELOADED, info.ZSwState_LOADED},
		{UNKNOWN, info.ZSwState_RUNNING},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.state.ZSwState(), "state=%v", tc.state)
	}
}

// UuidToNum.GetKey and AppInterfaceToNum.GetKey

func TestUuidToNumGetKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	u := &UuidToNum{UuidToNumKey: UuidToNumKey{UUID: id}}
	gotKey := u.GetKey()
	k, ok := gotKey.(UuidToNumKey)
	require.True(t, ok)
	assert.Equal(t, id, k.UUID)
}

func TestAppInterfaceToNumGetKey(t *testing.T) {
	netInstID := uuid.Must(uuid.NewV4())
	appID := uuid.Must(uuid.NewV4())
	aif := &AppInterfaceToNum{
		AppInterfaceKey: AppInterfaceKey{NetInstID: netInstID, AppID: appID, IfIdx: 2},
	}
	gotKey := aif.GetKey()
	k, ok := gotKey.(AppInterfaceKey)
	require.True(t, ok)
	assert.Equal(t, netInstID, k.NetInstID)
	assert.Equal(t, appID, k.AppID)
	assert.Equal(t, uint32(2), k.IfIdx)
}
