// Package networktraffic implements GET /api/events/network-traffic — a
// route the stock dashboard (netbirdio/dashboard, src/cloud/traffic-events/)
// already calls and is fully built to render, but which openapi.yml marks
// `x-cloud-only: true` and which open-source management never implements.
//
// This implementation reads from the Postgres database written by the
// independent traffic-event-logger flow server + ETL
// (https://github.com/ValarMarkhulis/traffic-event-logger), rather
// than duplicating flow collection inside management itself. See
// management/server/networktraffic/flowstore for that read path.
//
// Multi-tenant note: event_logs itself has no account_id column, since it's
// written by the independent flow server with no concept of NetBird
// accounts at all. This handler enforces account isolation itself: every
// query is restricted to the calling account's own peers' public keys
// (flowstore.Filter.AccountPublicKeys, derived from GetAccount below, and
// enforced fail-closed inside flowstore even if a caller forgot to set it).
// A single flowstore DSN can safely be shared across multiple NetBird
// accounts on this management server -- each account only ever sees rows
// reported by its own peers. See enricher.accountPublicKeys.
package networktraffic

import (
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/networktraffic/flowstore"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type handler struct {
	accountManager     account.Manager
	geolocationManager geolocation.Geolocation
	permissionsManager permissions.Manager
	flowStore          *flowstore.Store
}

// AddEndpoints registers the network-traffic events route. If flowStore is
// nil (NB_NETWORK_TRAFFIC_POSTGRES_DSN unset), it registers nothing — a
// self-hosted install without traffic-event-logger deployed simply
// doesn't get this route, the same graceful-absence pattern other optional
// integrations in this codebase use (compare the geolocationsHandler's nil
// geolocationManager check).
func AddEndpoints(accountManager account.Manager, geolocationManager geolocation.Geolocation, permissionsManager permissions.Manager, flowStore *flowstore.Store, router *mux.Router) {
	if flowStore == nil {
		return
	}
	h := &handler{
		accountManager:     accountManager,
		geolocationManager: geolocationManager,
		permissionsManager: permissionsManager,
		flowStore:          flowStore,
	}
	router.HandleFunc("/events/network-traffic", h.getNetworkTrafficEvents).Methods("GET", "OPTIONS")
}

func (h *handler) authenticate(r *http.Request) (accountID, userID string, err error) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		return "", "", err
	}
	accountID, userID = userAuth.AccountId, userAuth.UserId

	allowed, err := h.permissionsManager.ValidateUserPermissions(r.Context(), accountID, userID, modules.NetworkTraffic, operations.Read)
	if err != nil {
		return "", "", status.NewPermissionValidationError(err)
	}
	if !allowed {
		return "", "", status.NewPermissionDeniedError()
	}
	return accountID, userID, nil
}

func (h *handler) getNetworkTrafficEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, userID, err := h.authenticate(r)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	q, err := parseQuery(r.URL.Query())
	if err != nil {
		util.WriteError(ctx, status.Errorf(status.InvalidArgument, "%s", err), w)
		return
	}

	acc, err := h.accountManager.GetAccount(ctx, accountID)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	// Best-effort: GetUsersFromAccount is additionally gated on Users:Read.
	// A caller with only NetworkTraffic:Read gets an empty/limited map here,
	// which is fine — the response schema explicitly allows an empty user.
	userInfos, err := h.accountManager.GetUsersFromAccount(ctx, accountID, userID)
	if err != nil {
		log.WithContext(ctx).Warnf("network traffic events: user enrichment unavailable: %v", err)
		userInfos = map[string]*types.UserInfo{}
	}

	enricher := newEnricher(acc, h.geolocationManager)
	enricher.userInfos = userInfos

	accountPublicKeys := enricher.accountPublicKeys()
	if len(accountPublicKeys) == 0 {
		// No peers in this account yet -- short-circuit rather than ever
		// reaching flowstore. Not just an optimization: flowstore's own
		// fail-closed empty-allowlist handling would return the same
		// empty result, but this avoids a DB round trip for the common
		// brand-new-account case and keeps the "empty means deny" rule
		// enforced at both layers independently.
		util.WriteJSONObject(ctx, w, &api.NetworkTrafficEventsResponse{
			Data:         []api.NetworkTrafficEvent{},
			Page:         q.page,
			PageSize:     q.pageSize,
			TotalRecords: 0,
			TotalPages:   0,
		})
		return
	}

	filter := flowstore.Filter{
		AccountPublicKeys: accountPublicKeys,
		StartDate:         q.startDate,
		EndDate:           q.endDate,
		Direction:         q.direction,
		ProtocolNames:     q.protocolNames,
		EventType:         q.eventType,
		ConnectionType:    q.connectionType,
		SearchLike:        q.search,
	}

	if q.reporterID != "" {
		if pk := enricher.publicKeyForPeerID(q.reporterID); pk != "" {
			filter.PublicKeys = append(filter.PublicKeys, pk)
		} else {
			// Unknown reporter_id in this account — guarantee zero matches
			// rather than silently ignoring the filter.
			filter.PublicKeys = []string{notAPublicKeySentinel}
		}
	}
	if q.userID != "" {
		userKeys := enricher.publicKeysForUserID(q.userID)
		if len(userKeys) == 0 {
			filter.PublicKeys = []string{notAPublicKeySentinel}
		} else if len(filter.PublicKeys) == 0 {
			filter.PublicKeys = userKeys
		} else {
			filter.PublicKeys = intersect(filter.PublicKeys, userKeys)
			if len(filter.PublicKeys) == 0 {
				filter.PublicKeys = []string{notAPublicKeySentinel}
			}
		}
	}
	if q.search != "" {
		filter.SearchPublicKeys = enricher.publicKeysMatchingSearch(q.search)
	}

	groups, total, err := h.flowStore.QueryFlowGroups(ctx, filter, q.page, q.pageSize)
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}

	events := make([]api.NetworkTrafficEvent, 0, len(groups))
	for _, g := range groups {
		events = append(events, toAPIEvent(g, enricher))
	}

	totalPages := 0
	if total > 0 {
		totalPages = int((total + int64(q.pageSize) - 1) / int64(q.pageSize))
	}

	util.WriteJSONObject(ctx, w, &api.NetworkTrafficEventsResponse{
		Data:         events,
		Page:         q.page,
		PageSize:     q.pageSize,
		TotalRecords: int(total),
		TotalPages:   totalPages,
	})
}

// notAPublicKeySentinel is used to force a filter to match zero rows (e.g.
// an unknown reporter_id/user_id was supplied) without special-casing an
// empty-PublicKeys-means-"no filter" vs empty-PublicKeys-means-"filter to
// nothing" ambiguity in flowstore.Filter.
const notAPublicKeySentinel = "\x00no-such-peer\x00"

func intersect(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, v := range b {
		set[v] = struct{}{}
	}
	var out []string
	for _, v := range a {
		if _, ok := set[v]; ok {
			out = append(out, v)
		}
	}
	return out
}

func toAPIEvent(g flowstore.FlowGroup, e *enricher) api.NetworkTrafficEvent {
	latest := g.Rows[len(g.Rows)-1]

	subEvents := make([]api.NetworkTrafficSubEvent, 0, len(g.Rows))
	for _, row := range g.Rows {
		subEvents = append(subEvents, api.NetworkTrafficSubEvent{
			Type:      row.Type,
			Timestamp: row.EventTime,
		})
	}

	reporterID := g.PublicKey
	if peer, ok := e.peersByPubKey[g.PublicKey]; ok {
		reporterID = peer.ID
	}

	direction := "DIRECTION_UNKNOWN"
	switch latest.Direction {
	case "ingress":
		direction = "INGRESS"
	case "egress":
		direction = "EGRESS"
	}

	return api.NetworkTrafficEvent{
		FlowId:      g.FlowID,
		ReporterId:  reporterID,
		Source:      e.resolveEndpoint(latest.SourceIP, latest.SourceResourceID, latest.ConnSourcePort),
		Destination: e.resolveEndpoint(latest.DestIP, latest.DestResourceID, latest.ConnDestPort),
		User:        e.resolveUser(g.PublicKey),
		Policy:      e.resolvePolicy(latest.RuleID),
		Icmp: api.NetworkTrafficICMP{
			Type: int(latest.IcmpType),
			Code: int(latest.IcmpCode),
		},
		Protocol:  flowstore.ProtocolNameToNumber(latest.Protocol),
		Direction: direction,
		RxBytes:   int(latest.RxBytes),
		RxPackets: int(latest.RxPackets),
		TxBytes:   int(latest.TxBytes),
		TxPackets: int(latest.TxPackets),
		Events:    subEvents,
	}
}
