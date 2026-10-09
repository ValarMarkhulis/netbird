package networktraffic

import (
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/netbirdio/netbird/management/server/networktraffic/flowstore"
)

// query is the parsed, validated form of the GET /events/network-traffic
// query string, per shared/management/http/api/openapi.yml.
type query struct {
	page, pageSize int
	userID         string
	reporterID     string
	search         string
	protocolNames  []string
	eventType      string
	connectionType string
	// direction is the lowercase stored form ("ingress"/"egress"/"unknown"),
	// already translated from the API's uppercase enum.
	direction string
	startDate *time.Time
	endDate   *time.Time
}

const (
	defaultPage     = 1
	defaultPageSize = 1000
	maxPageSize     = 50000
)

func parseQuery(v url.Values) (query, error) {
	q := query{page: defaultPage, pageSize: defaultPageSize}

	if s := v.Get("page"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return q, fmt.Errorf("invalid page: %q", s)
		}
		q.page = n
	}

	if s := v.Get("page_size"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxPageSize {
			return q, fmt.Errorf("invalid page_size: %q", s)
		}
		q.pageSize = n
	}

	q.userID = v.Get("user_id")
	q.reporterID = v.Get("reporter_id")
	q.search = v.Get("search")

	if p := v.Get("protocol"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return q, fmt.Errorf("invalid protocol: %q", p)
		}
		q.protocolNames = flowstore.ProtocolNumberToNames(n)
	}

	if t := v.Get("type"); t != "" {
		switch t {
		case "TYPE_UNKNOWN", "TYPE_START", "TYPE_END", "TYPE_DROP":
			q.eventType = t
		default:
			return q, fmt.Errorf("invalid type: %q", t)
		}
	}

	if ct := v.Get("connection_type"); ct != "" {
		switch ct {
		case "P2P", "ROUTED":
			q.connectionType = ct
		default:
			return q, fmt.Errorf("invalid connection_type: %q", ct)
		}
	}

	if d := v.Get("direction"); d != "" {
		switch d {
		case "INGRESS":
			q.direction = "ingress"
		case "EGRESS":
			q.direction = "egress"
		case "DIRECTION_UNKNOWN":
			q.direction = "unknown"
		default:
			return q, fmt.Errorf("invalid direction: %q", d)
		}
	}

	if s := v.Get("start_date"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return q, fmt.Errorf("invalid start_date: %q", s)
		}
		q.startDate = &t
	}

	if s := v.Get("end_date"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return q, fmt.Errorf("invalid end_date: %q", s)
		}
		q.endDate = &t
	}

	return q, nil
}
