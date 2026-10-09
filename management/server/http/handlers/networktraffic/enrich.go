package networktraffic

import (
	"fmt"
	"net"
	"strings"

	"github.com/netbirdio/netbird/management/server/geolocation"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// enricher resolves raw event_logs identifiers (public keys, resource IDs,
// rule IDs, IPs) against the account's own peers/resources/policies/users.
// It's built once per request from a single GetAccount call and reused
// across every row in the response page — O(account size) once, not once
// per row.
type enricher struct {
	account *types.Account
	geo     geolocation.Geolocation

	peersByPubKey map[string]*nbpeer.Peer
	peersByID     map[string]*nbpeer.Peer
	peersByIP     map[string]*nbpeer.Peer
	resourcesByID map[string]*resourceTypes.NetworkResource
	ruleToPolicy  map[string]*types.Policy
	// userInfos is populated by the caller after construction (it requires
	// a separate, Users:Read-gated call — see handler.go) and may remain
	// empty if that permission isn't held; user enrichment then degrades to
	// just the peer's bare UserID, per the API's own "can be empty" contract.
	userInfos map[string]*types.UserInfo
}

func newEnricher(account *types.Account, geo geolocation.Geolocation) *enricher {
	e := &enricher{
		account:       account,
		geo:           geo,
		peersByPubKey: make(map[string]*nbpeer.Peer, len(account.Peers)),
		peersByID:     make(map[string]*nbpeer.Peer, len(account.Peers)),
		peersByIP:     make(map[string]*nbpeer.Peer, len(account.Peers)),
		resourcesByID: make(map[string]*resourceTypes.NetworkResource, len(account.NetworkResources)),
		ruleToPolicy:  map[string]*types.Policy{},
		userInfos:     map[string]*types.UserInfo{},
	}
	for _, p := range account.Peers {
		e.peersByPubKey[p.Key] = p
		e.peersByID[p.ID] = p
		if p.IP != nil {
			e.peersByIP[p.IP.String()] = p
		}
	}
	for _, res := range account.NetworkResources {
		e.resourcesByID[res.ID] = res
	}
	for _, pol := range account.Policies {
		for _, rule := range pol.Rules {
			e.ruleToPolicy[rule.ID] = pol
		}
	}
	return e
}

// accountPublicKeys returns every public key belonging to a peer in this
// account — the mandatory allowlist passed to flowstore as
// Filter.AccountPublicKeys, since event_logs itself has no account_id
// column. See the package doc on flowstore.Filter for why this must never
// be skipped.
func (e *enricher) accountPublicKeys() []string {
	keys := make([]string, 0, len(e.peersByPubKey))
	for pk := range e.peersByPubKey {
		keys = append(keys, pk)
	}
	return keys
}

// publicKeyForPeerID resolves a `reporter_id` query value (a peer ID) to its
// WireGuard public key — the only identifier event_logs rows carry. Returns
// "" if no such peer exists in the account.
func (e *enricher) publicKeyForPeerID(peerID string) string {
	if p, ok := e.peersByID[peerID]; ok {
		return p.Key
	}
	return ""
}

// publicKeysForUserID resolves a `user_id` query value to every public key
// of a peer that user registered.
func (e *enricher) publicKeysForUserID(userID string) []string {
	var keys []string
	for _, p := range e.account.Peers {
		if p.UserID == userID {
			keys = append(keys, p.Key)
		}
	}
	return keys
}

// publicKeysMatchingSearch resolves a free-text `search` value against peer
// names/DNS labels and, where available, user names/emails — returning the
// public keys of every peer that search should surface. The handler also
// ORs this against a plain IP substring match at the SQL level (see
// flowstore.Filter.SearchLike), so this only needs to cover the
// identity-name side of "partial match on user email, source/destination
// names, and source/destination addresses" from the API description.
func (e *enricher) publicKeysMatchingSearch(search string) []string {
	needle := strings.ToLower(search)
	seen := make(map[string]struct{})
	var keys []string
	add := func(k string) {
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			keys = append(keys, k)
		}
	}
	for _, p := range e.account.Peers {
		if strings.Contains(strings.ToLower(p.Name), needle) || strings.Contains(strings.ToLower(p.DNSLabel), needle) {
			add(p.Key)
		}
	}
	for uid, info := range e.userInfos {
		if strings.Contains(strings.ToLower(info.Email), needle) || strings.Contains(strings.ToLower(info.Name), needle) {
			for _, k := range e.publicKeysForUserID(uid) {
				add(k)
			}
		}
	}
	return keys
}

// resolveEndpoint builds a NetworkTrafficEndpoint for one side of a flow.
// Resolution order: network resource (if a resource ID was recorded) ->
// known peer (matched by its current overlay IP) -> an opaque "UNKNOWN"
// endpoint carrying just the raw IP. The schema requires every field to be
// present (GeoLocation non-nullable, etc.) so every branch returns a fully
// populated struct, never a partial one.
func (e *enricher) resolveEndpoint(ip, resourceID string, port uint32) api.NetworkTrafficEndpoint {
	address := formatAddress(ip, port)
	geo := e.geoLocation(ip)

	if resourceID != "" {
		if res, ok := e.resourcesByID[resourceID]; ok {
			return api.NetworkTrafficEndpoint{
				Id:          res.ID,
				Type:        resourceAPIType(res.Type),
				Name:        res.Name,
				GeoLocation: geo,
				Os:          nil,
				Address:     address,
				DnsLabel:    nil,
			}
		}
	}

	if peer, ok := e.peersByIP[ip]; ok {
		var os, dnsLabel *string
		if peer.Meta.OS != "" {
			v := peer.Meta.OS
			os = &v
		}
		if peer.DNSLabel != "" {
			v := peer.DNSLabel
			dnsLabel = &v
		}
		return api.NetworkTrafficEndpoint{
			Id:          peer.ID,
			Type:        "PEER",
			Name:        peer.Name,
			GeoLocation: geo,
			Os:          os,
			Address:     address,
			DnsLabel:    dnsLabel,
		}
	}

	name := ip
	if name == "" {
		name = "Unknown"
	}
	return api.NetworkTrafficEndpoint{
		Id:          ip,
		Type:        "UNKNOWN",
		Name:        name,
		GeoLocation: geo,
		Os:          nil,
		Address:     address,
		DnsLabel:    nil,
	}
}

// resolveUser resolves the NetworkTrafficUser for the peer that reported a
// flow — the OpenAPI schema explicitly documents this as "can be empty as
// not every event is user-initiated" (e.g. setup-key-provisioned peers), so
// a nil/unresolved reporter peer or empty UserID is expected, not an error.
func (e *enricher) resolveUser(reporterPublicKey string) api.NetworkTrafficUser {
	peer, ok := e.peersByPubKey[reporterPublicKey]
	if !ok || peer.UserID == "" {
		return api.NetworkTrafficUser{}
	}
	if info, ok := e.userInfos[peer.UserID]; ok {
		return api.NetworkTrafficUser{Id: info.ID, Email: info.Email, Name: info.Name}
	}
	// User enrichment wasn't available (Users:Read not held by the caller,
	// or IDP lookup failed) — still surface the raw ID per the schema.
	return api.NetworkTrafficUser{Id: peer.UserID}
}

// resolvePolicy maps a flow row's rule_id to the policy it belongs to.
// rule_id is empty whenever the flow wasn't a policy-matched routed
// connection (e.g. plain P2P traffic), in which case an empty
// NetworkTrafficPolicy is the correct, schema-compliant result.
func (e *enricher) resolvePolicy(ruleID string) api.NetworkTrafficPolicy {
	if ruleID == "" {
		return api.NetworkTrafficPolicy{}
	}
	if pol, ok := e.ruleToPolicy[ruleID]; ok {
		return api.NetworkTrafficPolicy{Id: pol.ID, Name: pol.Name}
	}
	return api.NetworkTrafficPolicy{}
}

func (e *enricher) geoLocation(ip string) api.NetworkTrafficLocation {
	if e.geo == nil || ip == "" {
		return api.NetworkTrafficLocation{}
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return api.NetworkTrafficLocation{}
	}
	rec, err := e.geo.Lookup(parsed)
	if err != nil {
		return api.NetworkTrafficLocation{}
	}
	return api.NetworkTrafficLocation{
		CityName:    rec.City.Names.En,
		CountryCode: rec.Country.ISOCode,
	}
}

func resourceAPIType(t resourceTypes.NetworkResourceType) string {
	switch t {
	case resourceTypes.Host:
		return "HOST_RESOURCE"
	case resourceTypes.Subnet:
		return "SUBNET_RESOURCE"
	case resourceTypes.Domain:
		return "DOMAIN_RESOURCE"
	default:
		return "UNKNOWN"
	}
}

// formatAddress encodes ip+port the way the dashboard's parseAddressPort
// expects: "ip:port" for IPv4, "[ipv6]:port" for IPv6, or the bare IP with
// no brackets at all when there's no port (parseAddressPort's fallback
// path handles a bracket-less bare address, v4 or v6, identically).
func formatAddress(ip string, port uint32) string {
	if ip == "" {
		return ""
	}
	if port == 0 {
		return ip
	}
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}
