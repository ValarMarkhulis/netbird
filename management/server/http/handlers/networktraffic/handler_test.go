package networktraffic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/networktraffic/flowstore"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func TestIntersect(t *testing.T) {
	assert.Equal(t, []string{"b"}, intersect([]string{"a", "b"}, []string{"b", "c"}))
	assert.Empty(t, intersect([]string{"a"}, []string{"b"}))
	assert.Empty(t, intersect(nil, []string{"a"}))
}

func TestAddEndpoints_NilFlowStoreRegistersNothing(t *testing.T) {
	router := mux.NewRouter()
	AddEndpoints(nil, &geolocation.Mock{}, nil, nil, router)

	req := httptest.NewRequest(http.MethodGet, "/events/network-traffic", nil)
	match := &mux.RouteMatch{}
	// A request for the route must not match any registered route when
	// flowStore is nil — self-hosted installs without
	// traffic-event-logger deployed simply don't get this endpoint.
	found := router.Match(req, match)
	assert.False(t, found)
}

func TestToAPIEvent_BasicMapping(t *testing.T) {
	e := newEnricher(testAccount(), &geolocation.Mock{})
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(5 * time.Second)

	group := flowstore.FlowGroup{
		PublicKey: "pubkey1",
		FlowID:    "flow1",
		Rows: []flowstore.EventLogRow{
			{
				PublicKey: "pubkey1", FlowID: "flow1", Type: "TYPE_START",
				CreatedAt: start, Protocol: "TCP", Direction: "egress",
				SourceIP: "100.64.0.1", DestIP: "100.64.0.2",
				ConnSourcePort: 51234, ConnDestPort: 443,
			},
			{
				PublicKey: "pubkey1", FlowID: "flow1", Type: "TYPE_END",
				CreatedAt: end, Protocol: "TCP", Direction: "egress",
				SourceIP: "100.64.0.1", DestIP: "100.64.0.2",
				ConnSourcePort: 51234, ConnDestPort: 443,
				RxBytes: 100, TxBytes: 200, RxPackets: 2, TxPackets: 3,
			},
		},
	}

	ev := toAPIEvent(group, e)

	assert.Equal(t, "flow1", ev.FlowId)
	assert.Equal(t, "peer1", ev.ReporterId) // resolved from pubkey1 -> peer1
	assert.Equal(t, "EGRESS", ev.Direction)
	assert.Equal(t, 6, ev.Protocol) // TCP -> 6
	// Counters come from the LATEST row (TYPE_END), not the first.
	assert.EqualValues(t, 100, ev.RxBytes)
	assert.EqualValues(t, 200, ev.TxBytes)
	assert.EqualValues(t, 2, ev.RxPackets)
	assert.EqualValues(t, 3, ev.TxPackets)
	// Both events are listed, in order.
	require.Len(t, ev.Events, 2)
	assert.Equal(t, "TYPE_START", ev.Events[0].Type)
	assert.Equal(t, "TYPE_END", ev.Events[1].Type)
	assert.True(t, ev.Events[0].Timestamp.Equal(start))
	assert.True(t, ev.Events[1].Timestamp.Equal(end))
	// icmp must always be a populated-but-zero object for a non-ICMP flow.
	assert.Equal(t, 0, ev.Icmp.Type)
	assert.Equal(t, 0, ev.Icmp.Code)
}

func TestToAPIEvent_UnresolvedReporterFallsBackToPublicKey(t *testing.T) {
	e := newEnricher(testAccount(), &geolocation.Mock{})
	group := flowstore.FlowGroup{
		PublicKey: "unknown-pubkey",
		FlowID:    "flow1",
		Rows: []flowstore.EventLogRow{
			{PublicKey: "unknown-pubkey", FlowID: "flow1", Type: "TYPE_START", CreatedAt: time.Now()},
		},
	}
	ev := toAPIEvent(group, e)
	assert.Equal(t, "unknown-pubkey", ev.ReporterId)
}

func TestToAPIEvent_UnknownDirectionMapsToDirectionUnknown(t *testing.T) {
	e := newEnricher(testAccount(), &geolocation.Mock{})
	group := flowstore.FlowGroup{
		PublicKey: "pubkey1",
		FlowID:    "flow1",
		Rows: []flowstore.EventLogRow{
			{PublicKey: "pubkey1", FlowID: "flow1", Type: "TYPE_START", Direction: "unknown", CreatedAt: time.Now()},
		},
	}
	ev := toAPIEvent(group, e)
	assert.Equal(t, "DIRECTION_UNKNOWN", ev.Direction)
}

// seedFlowStore opens an in-memory SQLite flowstore and seeds it with rows.
// Mirrors flowstore's own test helper (not exported across packages).
func seedFlowStore(t *testing.T, rows []flowstore.EventLogRow) *flowstore.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&flowstore.EventLogRow{}))
	if len(rows) > 0 {
		require.NoError(t, db.Create(&rows).Error)
	}
	return flowstore.NewWithDB(db)
}

func allowPermissionsMock(t *testing.T) permissions.Manager {
	t.Helper()
	ctrl := gomock.NewController(t)
	m := permissions.NewMockManager(ctrl)
	m.EXPECT().
		ValidateUserPermissions(gomock.Any(), gomock.Any(), gomock.Any(), modules.NetworkTraffic, operations.Read).
		Return(true, nil).
		AnyTimes()
	return m
}

func authedNetworkTrafficRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/events/network-traffic", nil)
	return nbcontext.SetUserAuthInRequest(req, nbcontext.UserAuth{
		UserId:    "user1",
		AccountId: "account1",
	})
}

// TestGetNetworkTrafficEvents_AccountIsolation is the end-to-end regression
// test for the account-boundary fix: two different accounts' peers' rows
// sit in the same event_logs table (a shared flowstore DSN), and the full
// HTTP handler path -- auth, enrichment, filter construction, flowstore
// query -- must only ever surface account1's own peer's row.
func TestGetNetworkTrafficEvents_AccountIsolation(t *testing.T) {
	flowStore := seedFlowStore(t, []flowstore.EventLogRow{
		{PublicKey: "pubkey1", FlowID: "f1", Type: "TYPE_START", CreatedAt: time.Now(), SourceIP: "10.0.0.1"},
		{PublicKey: "other-account-peer", FlowID: "f2", Type: "TYPE_START", CreatedAt: time.Now(), SourceIP: "10.0.0.2"},
	})

	h := &handler{
		accountManager: &mock_server.MockAccountManager{
			GetAccountFunc: func(ctx context.Context, accountID string) (*types.Account, error) {
				return testAccount(), nil // only has peers pubkey1/pubkey2
			},
			GetUsersFromAccountFunc: func(ctx context.Context, accountID, userID string) (map[string]*types.UserInfo, error) {
				return map[string]*types.UserInfo{}, nil
			},
		},
		geolocationManager: &geolocation.Mock{},
		permissionsManager: allowPermissionsMock(t),
		flowStore:          flowStore,
	}

	recorder := httptest.NewRecorder()
	h.getNetworkTrafficEvents(recorder, authedNetworkTrafficRequest())

	require.Equal(t, http.StatusOK, recorder.Code)
	var body api.NetworkTrafficEventsResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))

	require.Len(t, body.Data, 1, "must see exactly its own account's flow, never the other account's")
	assert.Equal(t, "f1", body.Data[0].FlowId)
	assert.EqualValues(t, 1, body.TotalRecords)
}

// TestGetNetworkTrafficEvents_ZeroPeersShortCircuits proves the short
// circuit actually skips flowstore entirely: the store wraps an already
// -closed DB connection, so any real query would error. A brand new
// account with no peers yet must still get a clean empty 200, not a
// 500 from a doomed query.
func TestGetNetworkTrafficEvents_ZeroPeersShortCircuits(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close()) // any query against this now errors

	h := &handler{
		accountManager: &mock_server.MockAccountManager{
			GetAccountFunc: func(ctx context.Context, accountID string) (*types.Account, error) {
				return &types.Account{Id: "account-brand-new"}, nil // no Peers
			},
			GetUsersFromAccountFunc: func(ctx context.Context, accountID, userID string) (map[string]*types.UserInfo, error) {
				return map[string]*types.UserInfo{}, nil
			},
		},
		geolocationManager: &geolocation.Mock{},
		permissionsManager: allowPermissionsMock(t),
		flowStore:          flowstore.NewWithDB(db),
	}

	recorder := httptest.NewRecorder()
	h.getNetworkTrafficEvents(recorder, authedNetworkTrafficRequest())

	require.Equal(t, http.StatusOK, recorder.Code)
	var body api.NetworkTrafficEventsResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Empty(t, body.Data)
	assert.EqualValues(t, 0, body.TotalRecords)
}
