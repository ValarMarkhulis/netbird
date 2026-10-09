// Package notifications implements the two read endpoints backing the
// dashboard's "Notifications" settings tab (netbirdio/dashboard,
// src/cloud/notifications/NotificationProvider.tsx): GET
// /api/integrations/notifications/types and GET
// /api/integrations/notifications/channels.
//
// That tab is license-gated client-side (canView = settings:read &&
// isLicensed), so it only started calling these once NETBIRD_LICENSED=true
// was set to unlock Traffic Events — that flag unlocks every Business-tier
// feature's UI at once, not just the one feature it was set for.
//
// SCOPE: this package makes the Notifications tab load without 404s and
// shows the real (empty) state — no notification channel is configured,
// which is true, since this fork doesn't implement outbound email/Slack/
// webhook delivery. It does NOT implement channel creation: a POST to
// /integrations/notifications/channels (clicking "Save" on a channel in the
// dashboard) will still 404. Silencing the read-only page load is a much
// smaller, safer scope than building actual notification delivery.
package notifications

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// eventTypeLabels mirrors the dashboard's NotificationEventType enum
// (src/interfaces/NotificationChannel.ts) — every key the dashboard knows
// how to render a checkbox for, with a human-readable label.
var eventTypeLabels = map[string]string{
	"peer.pending.approval":   "Peer Pending Approval",
	"peer.add":                "Peer Added",
	"routing.peer.disconnect": "Routing Peer Disconnected",
	"routing.peer.delete":     "Routing Peer Deleted",
	"user.pending.approval":   "User Pending Approval",
	"user.join":               "User Joined",
	"service.user.create":     "Service User Created",
	"idp.sync.token.expire":   "IdP Sync Token Expiring",
	"edr.sync.token.expire":   "EDR Sync Token Expiring",
}

// notificationChannel mirrors the dashboard's NotificationChannel interface
// (src/interfaces/NotificationChannel.ts) — defined here even though
// getChannels always returns an empty slice of it today, so the shape is
// already correct the day channel storage actually gets implemented.
type notificationChannel struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	Enabled    bool     `json:"enabled"`
	EventTypes []string `json:"event_types"`
}

type handler struct {
	accountManager     account.Manager
	permissionsManager permissions.Manager
}

func AddEndpoints(accountManager account.Manager, permissionsManager permissions.Manager, router *mux.Router) {
	h := &handler{accountManager: accountManager, permissionsManager: permissionsManager}
	router.HandleFunc("/integrations/notifications/types", h.getTypes).Methods("GET", "OPTIONS")
	router.HandleFunc("/integrations/notifications/channels", h.getChannels).Methods("GET", "OPTIONS")
}

func (h *handler) authenticate(r *http.Request) error {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		return err
	}
	allowed, err := h.permissionsManager.ValidateUserPermissions(r.Context(), userAuth.AccountId, userAuth.UserId, modules.Settings, operations.Read)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}
	return nil
}

func (h *handler) getTypes(w http.ResponseWriter, r *http.Request) {
	if err := h.authenticate(r); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, eventTypeLabels)
}

func (h *handler) getChannels(w http.ResponseWriter, r *http.Request) {
	if err := h.authenticate(r); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	// Honest empty state: no notification channel is configured, since this
	// fork doesn't implement outbound delivery. See the package doc comment.
	util.WriteJSONObject(r.Context(), w, []notificationChannel{})
}
