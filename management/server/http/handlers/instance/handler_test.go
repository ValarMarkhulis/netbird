package instance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetVersion(t *testing.T) {
	router := mux.NewRouter()
	AddEndpoints(router)

	req := httptest.NewRequest(http.MethodGet, "/instance/version", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)

	var body versionResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))

	// "Available" is reported equal to "current" — this fork doesn't track
	// upstream releases, so claiming otherwise would be misleading rather
	// than informative. See the handler's doc comment.
	assert.Equal(t, body.ManagementCurrentVersion, body.ManagementAvailableVersion)
	assert.NotEmpty(t, body.ManagementCurrentVersion)
	assert.Empty(t, body.DashboardAvailableVersion)
}
