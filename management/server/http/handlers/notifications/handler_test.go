package notifications

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
)

func newTestHandler(t *testing.T, allowed bool) *handler {
	t.Helper()
	ctrl := gomock.NewController(t)
	permissionsManagerMock := permissions.NewMockManager(ctrl)
	permissionsManagerMock.
		EXPECT().
		ValidateUserPermissions(gomock.Any(), gomock.Any(), gomock.Any(), modules.Settings, operations.Read).
		Return(allowed, nil).
		AnyTimes()

	return &handler{permissionsManager: permissionsManagerMock}
}

func authedRequest(method, path string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	return nbcontext.SetUserAuthInRequest(req, nbcontext.UserAuth{
		UserId:    "test_user",
		AccountId: "test_account",
	})
}

func TestGetTypes_ReturnsAllKnownEventTypes(t *testing.T) {
	h := newTestHandler(t, true)
	router := mux.NewRouter()
	router.HandleFunc("/integrations/notifications/types", h.getTypes).Methods("GET")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, authedRequest(http.MethodGet, "/integrations/notifications/types"))

	require.Equal(t, http.StatusOK, recorder.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	// Every key the dashboard's NotificationEventType enum knows about must
	// be present, or its checkbox list would silently drop an option.
	for _, key := range []string{
		"peer.pending.approval", "peer.add", "routing.peer.disconnect",
		"routing.peer.delete", "user.pending.approval", "user.join",
		"service.user.create", "idp.sync.token.expire", "edr.sync.token.expire",
	} {
		assert.Contains(t, body, key)
		assert.NotEmpty(t, body[key])
	}
}

func TestGetChannels_ReturnsEmptyArrayNotNull(t *testing.T) {
	h := newTestHandler(t, true)
	router := mux.NewRouter()
	router.HandleFunc("/integrations/notifications/channels", h.getChannels).Methods("GET")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, authedRequest(http.MethodGet, "/integrations/notifications/channels"))

	require.Equal(t, http.StatusOK, recorder.Code)
	// Must be "[]", not "null" — the dashboard calls .find()/.map() on this
	// directly without a null guard in places.
	assert.JSONEq(t, "[]", recorder.Body.String())
}

func TestGetTypes_DeniedWithoutSettingsReadPermission(t *testing.T) {
	h := newTestHandler(t, false)
	router := mux.NewRouter()
	router.HandleFunc("/integrations/notifications/types", h.getTypes).Methods("GET")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, authedRequest(http.MethodGet, "/integrations/notifications/types"))

	assert.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestGetChannels_DeniedWithoutSettingsReadPermission(t *testing.T) {
	h := newTestHandler(t, false)
	router := mux.NewRouter()
	router.HandleFunc("/integrations/notifications/channels", h.getChannels).Methods("GET")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, authedRequest(http.MethodGet, "/integrations/notifications/channels"))

	assert.Equal(t, http.StatusForbidden, recorder.Code)
}
