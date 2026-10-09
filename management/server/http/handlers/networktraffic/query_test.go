package networktraffic

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseQuery_Defaults(t *testing.T) {
	q, err := parseQuery(url.Values{})
	require.NoError(t, err)
	assert.Equal(t, defaultPage, q.page)
	assert.Equal(t, defaultPageSize, q.pageSize)
	assert.Empty(t, q.direction)
	assert.Nil(t, q.startDate)
	assert.Nil(t, q.endDate)
}

func TestParseQuery_PageAndPageSize(t *testing.T) {
	q, err := parseQuery(url.Values{"page": {"3"}, "page_size": {"50"}})
	require.NoError(t, err)
	assert.Equal(t, 3, q.page)
	assert.Equal(t, 50, q.pageSize)

	_, err = parseQuery(url.Values{"page": {"0"}})
	assert.Error(t, err)

	_, err = parseQuery(url.Values{"page": {"not-a-number"}})
	assert.Error(t, err)

	_, err = parseQuery(url.Values{"page_size": {"50001"}})
	assert.Error(t, err)

	_, err = parseQuery(url.Values{"page_size": {"0"}})
	assert.Error(t, err)
}

func TestParseQuery_Direction(t *testing.T) {
	cases := map[string]string{
		"INGRESS":           "ingress",
		"EGRESS":            "egress",
		"DIRECTION_UNKNOWN": "unknown",
	}
	for in, want := range cases {
		q, err := parseQuery(url.Values{"direction": {in}})
		require.NoError(t, err)
		assert.Equal(t, want, q.direction)
	}

	_, err := parseQuery(url.Values{"direction": {"sideways"}})
	assert.Error(t, err)
}

func TestParseQuery_Protocol(t *testing.T) {
	q, err := parseQuery(url.Values{"protocol": {"6"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"TCP"}, q.protocolNames)

	_, err = parseQuery(url.Values{"protocol": {"not-a-number"}})
	assert.Error(t, err)
}

func TestParseQuery_Type(t *testing.T) {
	q, err := parseQuery(url.Values{"type": {"TYPE_START"}})
	require.NoError(t, err)
	assert.Equal(t, "TYPE_START", q.eventType)

	_, err = parseQuery(url.Values{"type": {"NOT_A_TYPE"}})
	assert.Error(t, err)
}

func TestParseQuery_ConnectionType(t *testing.T) {
	q, err := parseQuery(url.Values{"connection_type": {"ROUTED"}})
	require.NoError(t, err)
	assert.Equal(t, "ROUTED", q.connectionType)

	_, err = parseQuery(url.Values{"connection_type": {"MESH"}})
	assert.Error(t, err)
}

func TestParseQuery_DateRange(t *testing.T) {
	q, err := parseQuery(url.Values{
		"start_date": {"2026-01-01T00:00:00Z"},
		"end_date":   {"2026-01-31T23:59:59Z"},
	})
	require.NoError(t, err)
	require.NotNil(t, q.startDate)
	require.NotNil(t, q.endDate)
	assert.True(t, q.startDate.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)))

	_, err = parseQuery(url.Values{"start_date": {"not-a-date"}})
	assert.Error(t, err)

	_, err = parseQuery(url.Values{"end_date": {"not-a-date"}})
	assert.Error(t, err)
}

func TestParseQuery_PassthroughFields(t *testing.T) {
	q, err := parseQuery(url.Values{
		"user_id":     {"u1"},
		"reporter_id": {"r1"},
		"search":      {"needle"},
	})
	require.NoError(t, err)
	assert.Equal(t, "u1", q.userID)
	assert.Equal(t, "r1", q.reporterID)
	assert.Equal(t, "needle", q.search)
}
