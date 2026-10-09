package networktraffic

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/networktraffic/flowstore"
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
