package networktraffic

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/geolocation"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func testAccount() *types.Account {
	return &types.Account{
		Id: "account1",
		Peers: map[string]*nbpeer.Peer{
			"peer1": {
				ID:       "peer1",
				Key:      "pubkey1",
				IP:       net.ParseIP("100.64.0.1"),
				Name:     "laptop-alice",
				DNSLabel: "laptop-alice.netbird",
				UserID:   "user1",
				Meta:     nbpeer.PeerSystemMeta{OS: "linux"},
			},
			"peer2": {
				ID:   "peer2",
				Key:  "pubkey2",
				IP:   net.ParseIP("100.64.0.2"),
				Name: "router",
				// No UserID: e.g. a setup-key-provisioned peer.
			},
		},
		NetworkResources: []*resourceTypes.NetworkResource{
			{ID: "res1", Name: "internal-web", Type: resourceTypes.Host},
			{ID: "res2", Name: "office-subnet", Type: resourceTypes.Subnet},
		},
		Policies: []*types.Policy{
			{
				ID:   "policy1",
				Name: "All to All",
				Rules: []*types.PolicyRule{
					{ID: "rule1", PolicyID: "policy1", Name: "allow-all"},
				},
			},
		},
	}
}

func TestEnricher_PublicKeyForPeerID(t *testing.T) {
	e := newEnricher(testAccount(), &geolocation.Mock{})
	assert.Equal(t, "pubkey1", e.publicKeyForPeerID("peer1"))
	assert.Equal(t, "", e.publicKeyForPeerID("no-such-peer"))
}

func TestEnricher_PublicKeysForUserID(t *testing.T) {
	e := newEnricher(testAccount(), &geolocation.Mock{})
	assert.Equal(t, []string{"pubkey1"}, e.publicKeysForUserID("user1"))
	assert.Empty(t, e.publicKeysForUserID("no-such-user"))
}

func TestEnricher_PublicKeysMatchingSearch_MatchesPeerName(t *testing.T) {
	e := newEnricher(testAccount(), &geolocation.Mock{})
	assert.Equal(t, []string{"pubkey1"}, e.publicKeysMatchingSearch("alice"))
	assert.Equal(t, []string{"pubkey2"}, e.publicKeysMatchingSearch("ROUTER"))
	assert.Empty(t, e.publicKeysMatchingSearch("nobody"))
}

func TestEnricher_PublicKeysMatchingSearch_MatchesUserEmail(t *testing.T) {
	e := newEnricher(testAccount(), &geolocation.Mock{})
	e.userInfos = map[string]*types.UserInfo{
		"user1": {ID: "user1", Email: "alice@example.com", Name: "Alice"},
	}
	assert.Equal(t, []string{"pubkey1"}, e.publicKeysMatchingSearch("alice@example"))
}

func TestEnricher_ResolveEndpoint_ResourcePriorityOverIP(t *testing.T) {
	e := newEnricher(testAccount(), &geolocation.Mock{})
	// Even though 100.64.0.1 matches peer1, a resource ID present on the row
	// should take priority (it's the more specific, authoritative identity).
	ep := e.resolveEndpoint("100.64.0.1", "res1", 443)
	assert.Equal(t, "res1", ep.Id)
	assert.Equal(t, "HOST_RESOURCE", ep.Type)
	assert.Equal(t, "internal-web", ep.Name)
	assert.Equal(t, "100.64.0.1:443", ep.Address)
}

func TestEnricher_ResolveEndpoint_KnownPeerByIP(t *testing.T) {
	e := newEnricher(testAccount(), &geolocation.Mock{})
	ep := e.resolveEndpoint("100.64.0.1", "", 51820)
	assert.Equal(t, "peer1", ep.Id)
	assert.Equal(t, "PEER", ep.Type)
	assert.Equal(t, "laptop-alice", ep.Name)
	require.NotNil(t, ep.Os)
	assert.Equal(t, "linux", *ep.Os)
	require.NotNil(t, ep.DnsLabel)
	assert.Equal(t, "laptop-alice.netbird", *ep.DnsLabel)
	assert.Equal(t, "100.64.0.1:51820", ep.Address)
}

func TestEnricher_ResolveEndpoint_UnknownIPFallsBackGracefully(t *testing.T) {
	e := newEnricher(testAccount(), &geolocation.Mock{})
	ep := e.resolveEndpoint("8.8.8.8", "", 0)
	assert.Equal(t, "8.8.8.8", ep.Id)
	assert.Equal(t, "UNKNOWN", ep.Type)
	assert.Equal(t, "8.8.8.8", ep.Name)
	assert.Nil(t, ep.Os)
	assert.Nil(t, ep.DnsLabel)
	// GeoLocation must always be a populated (if empty) struct, never a nil
	// pointer — the dashboard accesses it unguarded.
	assert.Equal(t, api.NetworkTrafficLocation{}, ep.GeoLocation)
}

func TestEnricher_ResolveEndpoint_UnknownResourceIDFallsThroughToIP(t *testing.T) {
	e := newEnricher(testAccount(), &geolocation.Mock{})
	// A resource ID that doesn't exist in this account (stale/deleted
	// resource) must not produce an error — fall through to IP resolution.
	ep := e.resolveEndpoint("100.64.0.2", "deleted-resource", 0)
	assert.Equal(t, "peer2", ep.Id)
	assert.Equal(t, "PEER", ep.Type)
}

func TestEnricher_ResolveUser(t *testing.T) {
	e := newEnricher(testAccount(), &geolocation.Mock{})
	e.userInfos = map[string]*types.UserInfo{
		"user1": {ID: "user1", Email: "alice@example.com", Name: "Alice"},
	}

	// Reporter peer1 has UserID "user1", which resolves fully.
	u := e.resolveUser("pubkey1")
	assert.Equal(t, api.NetworkTrafficUser{Id: "user1", Email: "alice@example.com", Name: "Alice"}, u)

	// Reporter peer2 has no UserID -> empty user, not an error.
	u2 := e.resolveUser("pubkey2")
	assert.Equal(t, api.NetworkTrafficUser{}, u2)

	// Unknown reporter public key -> empty user.
	u3 := e.resolveUser("no-such-key")
	assert.Equal(t, api.NetworkTrafficUser{}, u3)
}

func TestEnricher_ResolveUser_UserIDWithoutUserInfo(t *testing.T) {
	// userInfos wasn't populated (e.g. caller lacked Users:Read) — the raw
	// UserID should still surface per the schema's "can be empty" contract,
	// rather than silently dropping it entirely.
	e := newEnricher(testAccount(), &geolocation.Mock{})
	u := e.resolveUser("pubkey1")
	assert.Equal(t, api.NetworkTrafficUser{Id: "user1"}, u)
}

func TestEnricher_ResolvePolicy(t *testing.T) {
	e := newEnricher(testAccount(), &geolocation.Mock{})

	p := e.resolvePolicy("rule1")
	assert.Equal(t, api.NetworkTrafficPolicy{Id: "policy1", Name: "All to All"}, p)

	assert.Equal(t, api.NetworkTrafficPolicy{}, e.resolvePolicy(""))
	assert.Equal(t, api.NetworkTrafficPolicy{}, e.resolvePolicy("no-such-rule"))
}

type fakeGeo struct {
	city, country string
	err           error
}

func (f *fakeGeo) Lookup(net.IP) (*geolocation.Record, error) {
	if f.err != nil {
		return nil, f.err
	}
	rec := &geolocation.Record{}
	rec.City.Names.En = f.city
	rec.Country.ISOCode = f.country
	return rec, nil
}
func (f *fakeGeo) GetAllCountries() ([]geolocation.Country, error)       { return nil, nil }
func (f *fakeGeo) GetCitiesByCountry(string) ([]geolocation.City, error) { return nil, nil }
func (f *fakeGeo) Stop() error                                           { return nil }

func TestEnricher_GeoLocation(t *testing.T) {
	e := newEnricher(testAccount(), &fakeGeo{city: "Berlin", country: "DE"})
	loc := e.geoLocation("1.2.3.4")
	assert.Equal(t, api.NetworkTrafficLocation{CityName: "Berlin", CountryCode: "DE"}, loc)

	// nil geolocation manager (e.g. GeoLite2 DB not loaded on this
	// self-hosted install) -> empty, not a crash.
	e2 := newEnricher(testAccount(), nil)
	assert.Equal(t, api.NetworkTrafficLocation{}, e2.geoLocation("1.2.3.4"))

	// Empty/unparseable IP -> empty, not a crash.
	assert.Equal(t, api.NetworkTrafficLocation{}, e.geoLocation(""))
	assert.Equal(t, api.NetworkTrafficLocation{}, e.geoLocation("not-an-ip"))
}

func TestFormatAddress(t *testing.T) {
	cases := []struct {
		ip, want string
		port     uint32
	}{
		{ip: "", port: 443, want: ""},
		{ip: "10.0.0.1", port: 443, want: "10.0.0.1:443"},
		{ip: "10.0.0.1", port: 0, want: "10.0.0.1"},
		{ip: "fd00::1", port: 443, want: "[fd00::1]:443"},
		{ip: "fd00::1", port: 0, want: "fd00::1"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, formatAddress(c.ip, c.port), "ip=%s port=%d", c.ip, c.port)
	}
}

func TestResourceAPIType(t *testing.T) {
	assert.Equal(t, "HOST_RESOURCE", resourceAPIType(resourceTypes.Host))
	assert.Equal(t, "SUBNET_RESOURCE", resourceAPIType(resourceTypes.Subnet))
	assert.Equal(t, "DOMAIN_RESOURCE", resourceAPIType(resourceTypes.Domain))
	assert.Equal(t, "UNKNOWN", resourceAPIType(resourceTypes.NetworkResourceType("something-new")))
}
