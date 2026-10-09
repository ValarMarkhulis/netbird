package flowstore

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newTestStore opens an in-memory SQLite DB and seeds the event_logs table.
// The grouping/pagination SQL in this package is plain, portable SQL (no
// Postgres-only features), so SQLite is a faithful, fast stand-in for tests.
func newTestStore(t *testing.T, rows []EventLogRow) *Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&EventLogRow{}))
	if len(rows) > 0 {
		require.NoError(t, db.Create(&rows).Error)
	}
	return NewWithDB(db)
}

func ts(seconds int) time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(seconds) * time.Second)
}

func TestQueryFlowGroups_GroupsByPublicKeyAndFlowID(t *testing.T) {
	store := newTestStore(t, []EventLogRow{
		{PublicKey: "peerA", FlowID: "flow1", Type: "TYPE_START", EventTime: ts(0), Protocol: "TCP", SourceIP: "10.0.0.1", DestIP: "10.0.0.2"},
		{PublicKey: "peerA", FlowID: "flow1", Type: "TYPE_END", EventTime: ts(5), Protocol: "TCP", SourceIP: "10.0.0.1", DestIP: "10.0.0.2", RxBytes: 100},
		{PublicKey: "peerB", FlowID: "flow2", Type: "TYPE_START", EventTime: ts(1), Protocol: "UDP", SourceIP: "10.0.0.3", DestIP: "10.0.0.4"},
	})

	groups, total, err := store.QueryFlowGroups(context.Background(), Filter{AccountPublicKeys: []string{"peerA", "peerB"}}, 1, 10)
	require.NoError(t, err)
	assert.EqualValues(t, 2, total)
	require.Len(t, groups, 2)

	// Newest group (by earliest event) first: peerB's flow started at ts(1),
	// peerA's flow started at ts(0) — so peerB comes first.
	assert.Equal(t, "peerB", groups[0].PublicKey)
	assert.Equal(t, "flow2", groups[0].FlowID)
	assert.Len(t, groups[0].Rows, 1)

	assert.Equal(t, "peerA", groups[1].PublicKey)
	assert.Equal(t, "flow1", groups[1].FlowID)
	require.Len(t, groups[1].Rows, 2)
	// Rows within a group are sorted ascending by EventTime.
	assert.Equal(t, "TYPE_START", groups[1].Rows[0].Type)
	assert.Equal(t, "TYPE_END", groups[1].Rows[1].Type)
	assert.EqualValues(t, 100, groups[1].Rows[1].RxBytes)
}

func TestQueryFlowGroups_Pagination(t *testing.T) {
	rows := make([]EventLogRow, 0, 5)
	for i := 0; i < 5; i++ {
		rows = append(rows, EventLogRow{
			PublicKey: "peer", FlowID: "flow" + string(rune('0'+i)),
			Type: "TYPE_START", EventTime: ts(i), Protocol: "TCP",
		})
	}
	store := newTestStore(t, rows)

	page1, total, err := store.QueryFlowGroups(context.Background(), Filter{AccountPublicKeys: []string{"peer"}}, 1, 2)
	require.NoError(t, err)
	assert.EqualValues(t, 5, total)
	assert.Len(t, page1, 2)
	// Newest first: flow4 (ts=4), flow3 (ts=3)
	assert.Equal(t, "flow4", page1[0].FlowID)
	assert.Equal(t, "flow3", page1[1].FlowID)

	page2, total, err := store.QueryFlowGroups(context.Background(), Filter{AccountPublicKeys: []string{"peer"}}, 2, 2)
	require.NoError(t, err)
	assert.EqualValues(t, 5, total)
	assert.Len(t, page2, 2)
	assert.Equal(t, "flow2", page2[0].FlowID)
	assert.Equal(t, "flow1", page2[1].FlowID)

	page3, total, err := store.QueryFlowGroups(context.Background(), Filter{AccountPublicKeys: []string{"peer"}}, 3, 2)
	require.NoError(t, err)
	assert.EqualValues(t, 5, total)
	require.Len(t, page3, 1)
	assert.Equal(t, "flow0", page3[0].FlowID)
}

func TestQueryFlowGroups_FilterByDateRange(t *testing.T) {
	store := newTestStore(t, []EventLogRow{
		{PublicKey: "p", FlowID: "old", Type: "TYPE_START", EventTime: ts(0)},
		{PublicKey: "p", FlowID: "new", Type: "TYPE_START", EventTime: ts(100)},
	})

	start := ts(50)
	groups, total, err := store.QueryFlowGroups(context.Background(), Filter{AccountPublicKeys: []string{"p"}, StartDate: &start}, 1, 10)
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, groups, 1)
	assert.Equal(t, "new", groups[0].FlowID)
}

func TestQueryFlowGroups_FilterByPublicKeys(t *testing.T) {
	store := newTestStore(t, []EventLogRow{
		{PublicKey: "peerA", FlowID: "f1", Type: "TYPE_START", EventTime: ts(0)},
		{PublicKey: "peerB", FlowID: "f2", Type: "TYPE_START", EventTime: ts(1)},
	})

	groups, total, err := store.QueryFlowGroups(context.Background(), Filter{AccountPublicKeys: []string{"peerA", "peerB"}, PublicKeys: []string{"peerA"}}, 1, 10)
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, groups, 1)
	assert.Equal(t, "peerA", groups[0].PublicKey)
}

func TestQueryFlowGroups_FilterByDirection(t *testing.T) {
	store := newTestStore(t, []EventLogRow{
		{PublicKey: "p", FlowID: "in", Type: "TYPE_START", Direction: "ingress", EventTime: ts(0)},
		{PublicKey: "p", FlowID: "out", Type: "TYPE_START", Direction: "egress", EventTime: ts(1)},
	})

	groups, total, err := store.QueryFlowGroups(context.Background(), Filter{AccountPublicKeys: []string{"p"}, Direction: "egress"}, 1, 10)
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, groups, 1)
	assert.Equal(t, "out", groups[0].FlowID)
}

func TestQueryFlowGroups_FilterByProtocolNames(t *testing.T) {
	store := newTestStore(t, []EventLogRow{
		{PublicKey: "p", FlowID: "tcp", Type: "TYPE_START", Protocol: "TCP", EventTime: ts(0)},
		{PublicKey: "p", FlowID: "udp", Type: "TYPE_START", Protocol: "UDP", EventTime: ts(1)},
	})

	groups, total, err := store.QueryFlowGroups(context.Background(), Filter{AccountPublicKeys: []string{"p"}, ProtocolNames: ProtocolNumberToNames(17)}, 1, 10)
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, groups, 1)
	assert.Equal(t, "udp", groups[0].FlowID)
}

func TestQueryFlowGroups_FilterByConnectionType(t *testing.T) {
	store := newTestStore(t, []EventLogRow{
		{PublicKey: "p", FlowID: "p2p", Type: "TYPE_START", EventTime: ts(0)},
		{PublicKey: "p", FlowID: "routed", Type: "TYPE_START", DestResourceID: "res1", EventTime: ts(1)},
	})

	routed, total, err := store.QueryFlowGroups(context.Background(), Filter{AccountPublicKeys: []string{"p"}, ConnectionType: "ROUTED"}, 1, 10)
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, routed, 1)
	assert.Equal(t, "routed", routed[0].FlowID)

	p2p, total, err := store.QueryFlowGroups(context.Background(), Filter{AccountPublicKeys: []string{"p"}, ConnectionType: "P2P"}, 1, 10)
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, p2p, 1)
	assert.Equal(t, "p2p", p2p[0].FlowID)
}

func TestQueryFlowGroups_SearchLikeMatchesIPSubstring(t *testing.T) {
	store := newTestStore(t, []EventLogRow{
		{PublicKey: "p", FlowID: "match", Type: "TYPE_START", SourceIP: "100.64.1.5", EventTime: ts(0)},
		{PublicKey: "p", FlowID: "nomatch", Type: "TYPE_START", SourceIP: "10.0.0.1", EventTime: ts(1)},
	})

	groups, total, err := store.QueryFlowGroups(context.Background(), Filter{AccountPublicKeys: []string{"p"}, SearchLike: "100.64"}, 1, 10)
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, groups, 1)
	assert.Equal(t, "match", groups[0].FlowID)
}

func TestQueryFlowGroups_SearchPublicKeysComposesWithPagination(t *testing.T) {
	// search resolved to a candidate public key must still produce an exact
	// total_records count, not just filter within a page.
	store := newTestStore(t, []EventLogRow{
		{PublicKey: "aliceKey", FlowID: "f1", Type: "TYPE_START", SourceIP: "1.1.1.1", EventTime: ts(0)},
		{PublicKey: "bobKey", FlowID: "f2", Type: "TYPE_START", SourceIP: "2.2.2.2", EventTime: ts(1)},
	})

	groups, total, err := store.QueryFlowGroups(context.Background(), Filter{AccountPublicKeys: []string{"aliceKey", "bobKey"}, SearchPublicKeys: []string{"aliceKey"}}, 1, 10)
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, groups, 1)
	assert.Equal(t, "aliceKey", groups[0].PublicKey)
}

func TestQueryFlowGroups_NoMatches(t *testing.T) {
	store := newTestStore(t, []EventLogRow{
		{PublicKey: "p", FlowID: "f1", Type: "TYPE_START", EventTime: ts(0)},
	})

	groups, total, err := store.QueryFlowGroups(context.Background(), Filter{AccountPublicKeys: []string{"p"}, PublicKeys: []string{"nobody"}}, 1, 10)
	require.NoError(t, err)
	assert.EqualValues(t, 0, total)
	assert.Empty(t, groups)
}

func TestQueryFlowGroups_AccountPublicKeysEnforcesIsolation(t *testing.T) {
	// Two different accounts' peers' events sitting in the same event_logs
	// table (a single flowstore DSN shared across multiple NetBird
	// accounts, as infrastructure_files/setup.env.example now documents as
	// safe). Querying as one account must never surface the other's rows,
	// even with every other filter left wide open.
	store := newTestStore(t, []EventLogRow{
		{PublicKey: "account1-peer", FlowID: "f1", Type: "TYPE_START", EventTime: ts(0), SourceIP: "10.0.0.1"},
		{PublicKey: "account2-peer", FlowID: "f2", Type: "TYPE_START", EventTime: ts(1), SourceIP: "10.0.0.2"},
	})

	groups, total, err := store.QueryFlowGroups(context.Background(), Filter{
		AccountPublicKeys: []string{"account1-peer"},
	}, 1, 10)
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, groups, 1)
	assert.Equal(t, "account1-peer", groups[0].PublicKey)

	// Querying as the other account sees only its own peer's row.
	groups, total, err = store.QueryFlowGroups(context.Background(), Filter{
		AccountPublicKeys: []string{"account2-peer"},
	}, 1, 10)
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, groups, 1)
	assert.Equal(t, "account2-peer", groups[0].PublicKey)
}

func TestQueryFlowGroups_EmptyAccountPublicKeysMatchesNothing(t *testing.T) {
	// The fail-closed guarantee: forgetting to set AccountPublicKeys (a
	// caller bug) must drop all data, never silently return everything.
	store := newTestStore(t, []EventLogRow{
		{PublicKey: "p", FlowID: "f1", Type: "TYPE_START", EventTime: ts(0)},
	})

	groups, total, err := store.QueryFlowGroups(context.Background(), Filter{}, 1, 10)
	require.NoError(t, err)
	assert.EqualValues(t, 0, total)
	assert.Empty(t, groups)
}

func TestProtocolNumberNameRoundTrip(t *testing.T) {
	cases := map[int]string{1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 132: "SCTP"}
	for num, name := range cases {
		assert.Equal(t, []string{name}, ProtocolNumberToNames(num))
		assert.Equal(t, num, ProtocolNameToNumber(name))
	}
	// Unknown protocol numbers round-trip through their decimal string form,
	// matching database.Protocol.String()'s fallback in
	// traffic-event-logger.
	assert.Equal(t, []string{"47"}, ProtocolNumberToNames(47))
	assert.Equal(t, 47, ProtocolNameToNumber("47"))
	assert.Equal(t, 0, ProtocolNameToNumber("garbage"))
}

// One report batch can carry a flow's END before its START (and both arrive
// long after they happened); rows and groups must follow event_time.
func TestQueryFlowGroups_OrdersByEventTimeNotInsertOrder(t *testing.T) {
	store := newTestStore(t, []EventLogRow{
		{PublicKey: "p", FlowID: "long", Type: "TYPE_END", EventTime: ts(50)},
		{PublicKey: "p", FlowID: "long", Type: "TYPE_START", EventTime: ts(5)},
		{PublicKey: "p", FlowID: "later", Type: "TYPE_START", EventTime: ts(30)},
	})

	groups, _, err := store.QueryFlowGroups(context.Background(), Filter{AccountPublicKeys: []string{"p"}}, 1, 10)
	require.NoError(t, err)
	require.Len(t, groups, 2)
	assert.Equal(t, "later", groups[0].FlowID, "newest flow by first event time first")
	require.Len(t, groups[1].Rows, 2)
	assert.Equal(t, "TYPE_START", groups[1].Rows[0].Type)
	assert.Equal(t, "TYPE_END", groups[1].Rows[1].Type)
}

func TestQueryFlowGroups_DateRangeFiltersOnEventTime(t *testing.T) {
	store := newTestStore(t, []EventLogRow{
		{PublicKey: "p", FlowID: "before", Type: "TYPE_START", EventTime: ts(5)},
		{PublicKey: "p", FlowID: "inside", Type: "TYPE_START", EventTime: ts(20)},
		{PublicKey: "p", FlowID: "after", Type: "TYPE_START", EventTime: ts(40)},
	})

	start, end := ts(10), ts(30)
	groups, total, err := store.QueryFlowGroups(context.Background(), Filter{AccountPublicKeys: []string{"p"}, StartDate: &start, EndDate: &end}, 1, 10)
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, groups, 1)
	assert.Equal(t, "inside", groups[0].FlowID)
}
