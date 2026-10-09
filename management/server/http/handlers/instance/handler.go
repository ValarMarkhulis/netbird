// Package instance implements GET /api/instance/version — called
// unconditionally by every self-hosted dashboard (netbirdio/dashboard,
// src/components/VersionInfo.tsx: NavigationVersionInfo), gated only on
// "this isn't NetBird Cloud", not on license. Open-source management never
// implemented it, so self-hosted installs get a silent 404 (the dashboard
// passes ignoreErrors=true, so it just shows nothing rather than crashing).
package instance

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/version"
)

// versionResponse mirrors the dashboard's VersionInfo interface
// (src/interfaces/Instance.ts) field-for-field.
type versionResponse struct {
	ManagementCurrentVersion   string `json:"management_current_version"`
	ManagementAvailableVersion string `json:"management_available_version"`
	DashboardAvailableVersion  string `json:"dashboard_available_version"`
}

func AddEndpoints(router *mux.Router) {
	router.HandleFunc("/instance/version", getVersion).Methods("GET", "OPTIONS")
}

// getVersion reports the running version and, deliberately, claims it's
// already the "available" one. This fork is an intentionally pinned, patched
// build that doesn't track upstream netbirdio/netbird releases — reporting a
// real upstream version as "available" would nag an admin to "upgrade" into a
// build that drops this fork's patches. Equal-to-current is the honest answer
// for what this deployment actually tracks; dashboard_available_version is
// left empty for the same reason (management has no way to know the
// dashboard's build-time version either way — that comparison only ever runs
// client-side, per the dashboard's own code).
func getVersion(w http.ResponseWriter, r *http.Request) {
	current := version.NetbirdVersion()
	util.WriteJSONObject(r.Context(), w, &versionResponse{
		ManagementCurrentVersion:   current,
		ManagementAvailableVersion: current,
		DashboardAvailableVersion:  "",
	})
}
