// Package flowstore is a read-only client for the Postgres database written
// by the independent traffic-event-logger flow server + ETL
// (https://github.com/ValarMarkhulis/traffic-event-logger). It is
// deliberately separate from the management server's own account store:
// it never writes, and it has no notion of NetBird accounts (the
// event_logs table is single-tenant — see the package-level caveat in
// management/server/http/handlers/networktraffic).
package flowstore

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// EventLogRow mirrors the event_logs table's columns (see
// database.EventLog/database.FlowFields in traffic-event-logger).
// This package only ever reads from it, never migrates or writes it.
type EventLogRow struct {
	ID               uint      `gorm:"column:id"`
	CreatedAt        time.Time `gorm:"column:created_at"`
	PublicKey        string    `gorm:"column:public_key"`
	FlowID           string    `gorm:"column:flow_id"`
	Type             string    `gorm:"column:type"`
	RuleID           string    `gorm:"column:rule_id"`
	SourceResourceID string    `gorm:"column:source_resource_id"`
	DestResourceID   string    `gorm:"column:dest_resource_id"`
	Direction        string    `gorm:"column:direction"`
	Protocol         string    `gorm:"column:protocol"`
	SourceIP         string    `gorm:"column:source_ip"`
	DestIP           string    `gorm:"column:dest_ip"`
	ConnSourcePort   uint32    `gorm:"column:conn_source_port"`
	ConnDestPort     uint32    `gorm:"column:conn_dest_port"`
	IcmpType         uint32    `gorm:"column:icmp_icmp_type"`
	IcmpCode         uint32    `gorm:"column:icmp_icmp_code"`
	RxPackets        uint64    `gorm:"column:rx_packets"`
	TxPackets        uint64    `gorm:"column:tx_packets"`
	RxBytes          uint64    `gorm:"column:rx_bytes"`
	TxBytes          uint64    `gorm:"column:tx_bytes"`
}

// TableName pins the GORM table name — this package never auto-migrates,
// but GORM still needs this for query building.
func (EventLogRow) TableName() string { return "event_logs" }

// FlowGroup is every event_logs row sharing one (public_key, flow_id) pair —
// i.e. one reporter's view of one local flow, START through END/DROP. This
// is the unit a NetworkTrafficEvent is built from; see the handler package
// for why this is the right grouping (not a cross-peer merged session).
type FlowGroup struct {
	PublicKey string
	FlowID    string
	// Rows is sorted by CreatedAt ascending.
	Rows []EventLogRow
}

// Filter narrows QueryFlowGroups. All fields are optional; zero-value means
// "don't filter on this". Values that require resolving against the
// management account store (reporter_id/user_id -> public key, a text
// search against peer/resource/user names -> candidate public keys) are
// expected to already be resolved by the caller — this package only knows
// about event_logs, not peers/accounts.
type Filter struct {
	StartDate *time.Time
	EndDate   *time.Time
	// PublicKeys, if non-empty, restricts results to rows reported by one
	// of these peers (used for reporter_id/user_id filters).
	PublicKeys []string
	// Direction matches the stored lowercase value ("ingress"/"egress").
	// Empty means no filter.
	Direction string
	// ProtocolNames matches the stored protocol string(s) for a given
	// numeric protocol filter — see ProtocolNumberToNames.
	ProtocolNames []string
	// EventType matches the stored `type` column verbatim (e.g. "TYPE_START").
	EventType string
	// ConnectionType is "P2P" (neither resource ID set) or "ROUTED" (either
	// is set). Empty means no filter.
	ConnectionType string
	// SearchLike is matched case-insensitively against source_ip/dest_ip.
	SearchLike string
	// SearchPublicKeys additionally matches rows reported by one of these
	// peers — the caller resolves `search` against peer/resource/user names
	// first and passes the matches here, so a name search still composes
	// with SQL-level pagination instead of breaking it.
	SearchPublicKeys []string
}

type Store struct {
	db *gorm.DB
}

// New opens a read-only connection pool against dsn. Call Close when done.
func New(dsn string) (*Store, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("connect to network traffic database: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get underlying sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(10)
	sqlDB.SetMaxIdleConns(2)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)
	return &Store{db: db}, nil
}

// NewWithDB wraps an already-open *gorm.DB — used by tests (e.g. an
// in-memory SQLite DB), since the grouping/pagination SQL in this package
// is plain, portable SQL and doesn't rely on any Postgres-only feature.
func NewWithDB(db *gorm.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// QueryFlowGroups returns page `page` (1-based) of (public_key, flow_id)
// groups matching f, ordered by their earliest event descending (newest
// flows first), along with the total number of matching groups.
func (s *Store) QueryFlowGroups(ctx context.Context, f Filter, page, pageSize int) ([]FlowGroup, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 1000
	}
	if pageSize > 50000 {
		pageSize = 50000
	}

	type groupKey struct {
		PublicKey string
		FlowID    string
	}

	filtered := applyFilter(s.db.WithContext(ctx).Model(&EventLogRow{}), f)

	var keys []groupKey
	err := filtered.Session(&gorm.Session{}).
		Select("public_key, flow_id, MIN(created_at) as first_seen").
		Group("public_key, flow_id").
		Order("first_seen DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Scan(&keys).Error
	if err != nil {
		return nil, 0, fmt.Errorf("query flow groups: %w", err)
	}

	var total int64
	countSubquery := applyFilter(s.db.WithContext(ctx).Model(&EventLogRow{}), f).
		Session(&gorm.Session{}).
		Select("1").
		Group("public_key, flow_id")
	if err := s.db.WithContext(ctx).Table("(?) as grouped", countSubquery).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count flow groups: %w", err)
	}

	if len(keys) == 0 {
		return nil, total, nil
	}

	placeholders := make([]string, len(keys))
	args := make([]interface{}, 0, len(keys)*2)
	for i, k := range keys {
		placeholders[i] = "(?,?)"
		args = append(args, k.PublicKey, k.FlowID)
	}
	whereSQL := fmt.Sprintf("(public_key, flow_id) IN (%s)", strings.Join(placeholders, ","))

	var rows []EventLogRow
	if err := s.db.WithContext(ctx).Model(&EventLogRow{}).
		Where(whereSQL, args...).
		Order("created_at ASC").
		Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("fetch flow group rows: %w", err)
	}

	byKey := make(map[string][]EventLogRow, len(keys))
	for _, r := range rows {
		k := r.PublicKey + "\x00" + r.FlowID
		byKey[k] = append(byKey[k], r)
	}

	groups := make([]FlowGroup, 0, len(keys))
	for _, k := range keys {
		groups = append(groups, FlowGroup{
			PublicKey: k.PublicKey,
			FlowID:    k.FlowID,
			Rows:      byKey[k.PublicKey+"\x00"+k.FlowID],
		})
	}
	return groups, total, nil
}

func applyFilter(q *gorm.DB, f Filter) *gorm.DB {
	if f.StartDate != nil {
		q = q.Where("created_at >= ?", *f.StartDate)
	}
	if f.EndDate != nil {
		q = q.Where("created_at <= ?", *f.EndDate)
	}
	if len(f.PublicKeys) > 0 {
		q = q.Where("public_key IN ?", f.PublicKeys)
	}
	if f.Direction != "" {
		q = q.Where("direction = ?", f.Direction)
	}
	if len(f.ProtocolNames) > 0 {
		q = q.Where("protocol IN ?", f.ProtocolNames)
	}
	if f.EventType != "" {
		q = q.Where("type = ?", f.EventType)
	}
	switch f.ConnectionType {
	case "ROUTED":
		q = q.Where("(source_resource_id <> '' AND source_resource_id IS NOT NULL) OR (dest_resource_id <> '' AND dest_resource_id IS NOT NULL)")
	case "P2P":
		q = q.Where("(source_resource_id = '' OR source_resource_id IS NULL) AND (dest_resource_id = '' OR dest_resource_id IS NULL)")
	}
	if f.SearchLike != "" {
		like := "%" + strings.ToLower(f.SearchLike) + "%"
		clause := "(LOWER(source_ip) LIKE ? OR LOWER(dest_ip) LIKE ?"
		args := []interface{}{like, like}
		if len(f.SearchPublicKeys) > 0 {
			clause += " OR public_key IN ?"
			args = append(args, f.SearchPublicKeys)
		}
		clause += ")"
		q = q.Where(clause, args...)
	} else if len(f.SearchPublicKeys) > 0 {
		q = q.Where("public_key IN ?", f.SearchPublicKeys)
	}
	return q
}

// ProtocolNumberToNames returns the event_logs.protocol string value(s) a
// given IANA protocol number would have been stored as, mirroring
// database.Protocol.String() in traffic-event-logger.
func ProtocolNumberToNames(n int) []string {
	switch n {
	case 1:
		return []string{"ICMP"}
	case 6:
		return []string{"TCP"}
	case 17:
		return []string{"UDP"}
	case 58:
		return []string{"ICMPv6"}
	case 132:
		return []string{"SCTP"}
	default:
		return []string{strconv.Itoa(n)}
	}
}

// ProtocolNameToNumber is the inverse of ProtocolNumberToNames, used when
// mapping a stored row back to the API's numeric protocol field.
func ProtocolNameToNumber(name string) int {
	switch name {
	case "ICMP":
		return 1
	case "TCP":
		return 6
	case "UDP":
		return 17
	case "ICMPv6":
		return 58
	case "SCTP":
		return 132
	default:
		if n, err := strconv.Atoi(name); err == nil {
			return n
		}
		return 0
	}
}
