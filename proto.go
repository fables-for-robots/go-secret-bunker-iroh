package secretbunker

// Wire types mirroring the Rust server's proto.rs, CBOR-encoded in serde's
// externally-tagged enum representation: unit variants are text strings,
// all others are single-entry maps keyed by the variant name, with struct
// fields as text-keyed map entries and tuples as arrays. Variant and field
// NAMES are the wire contract, shared with the Rust repo's
// wire_format_is_stable test — never rename.

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ALPN is the protocol identifier for bunker connections.
const ALPN = "secret-bunker/1"

// MaxMessage is the largest encoded message accepted on a stream.
const MaxMessage = 4 * 1024 * 1024

// Permission bits.
const (
	PermRead  byte = 1
	PermWrite byte = 2
	PermAdmin byte = 4
)

func marshal(v any) []byte {
	buf, err := cbor.Marshal(v)
	if err != nil {
		// Only reachable via a bug in the fixed shapes below.
		panic(fmt.Sprintf("secretbunker: encoding request: %v", err))
	}
	return buf
}

func encGet(group, name string) []byte {
	return marshal(map[string]any{"Get": struct {
		Group string `cbor:"group"`
		Name  string `cbor:"name"`
	}{group, name}})
}

func encPut(group, name string, value []byte, expectedVersion uint64) []byte {
	if value == nil {
		value = []byte{}
	}
	return marshal(map[string]any{"Put": struct {
		Group           string `cbor:"group"`
		Name            string `cbor:"name"`
		Value           []byte `cbor:"value"`
		ExpectedVersion uint64 `cbor:"expected_version"`
	}{group, name, value, expectedVersion}})
}

func encDelete(group, name string, expectedVersion uint64) []byte {
	return marshal(map[string]any{"Delete": struct {
		Group           string `cbor:"group"`
		Name            string `cbor:"name"`
		ExpectedVersion uint64 `cbor:"expected_version"`
	}{group, name, expectedVersion}})
}

func encList(group string) []byte {
	return marshal(map[string]any{"List": struct {
		Group string `cbor:"group"`
	}{group}})
}

func encCreateGroup(name string) []byte {
	return marshal(map[string]any{"CreateGroup": struct {
		Name string `cbor:"name"`
	}{name}})
}

func encAddIdentity(name, endpointID string, serviceAdmin bool) []byte {
	return marshal(map[string]any{"AddIdentity": struct {
		Name         string `cbor:"name"`
		EndpointID   string `cbor:"endpoint_id"`
		ServiceAdmin bool   `cbor:"service_admin"`
	}{name, endpointID, serviceAdmin}})
}

func encRemoveIdentity(name string) []byte {
	return marshal(map[string]any{"RemoveIdentity": struct {
		Name string `cbor:"name"`
	}{name}})
}

func encListIdentities() []byte {
	return marshal("ListIdentities")
}

func encGrant(group, identity string, perms byte) []byte {
	return marshal(map[string]any{"Grant": struct {
		Group    string `cbor:"group"`
		Identity string `cbor:"identity"`
		Perms    byte   `cbor:"perms"`
	}{group, identity, perms}})
}

func encRotateDek(group string) []byte {
	return marshal(map[string]any{"RotateDek": struct {
		Group string `cbor:"group"`
	}{group}})
}

func encListGroups() []byte {
	return marshal("ListGroups")
}

func encGroupAcl(group string) []byte {
	return marshal(map[string]any{"GroupAcl": struct {
		Group string `cbor:"group"`
	}{group}})
}

func encListIdentityNames(group string) []byte {
	return marshal(map[string]any{"ListIdentityNames": struct {
		Group string `cbor:"group"`
	}{group}})
}

// NameVersion is one entry of a secret listing (a Rust `(String, u64)`
// tuple on the wire, i.e. a two-element array).
type NameVersion struct {
	_       struct{} `cbor:",toarray"`
	Name    string
	Version uint64
}

// IdentityInfo describes a registered identity.
type IdentityInfo struct {
	Name         string `cbor:"name"`
	EndpointID   string `cbor:"endpoint_id"`
	ServiceAdmin bool   `cbor:"service_admin"`
}

// GroupInfo is one entry of a group listing, with the caller's own
// permission bitmask on that group.
type GroupInfo struct {
	Name  string `cbor:"name"`
	Perms byte   `cbor:"perms"`
}

// ACLEntry is one identity's permissions on a group (a `(String, u8)`
// tuple on the wire).
type ACLEntry struct {
	_        struct{} `cbor:",toarray"`
	Identity string
	Perms    byte
}

// Response is the decoded server reply. Exactly one of the concrete types
// below.
type Response interface{ isResponse() }

// Denied is the uniform denial: unknown identity, missing permission, or
// nonexistent target — deliberately indistinguishable.
type Denied struct{}

// OK is a generic success.
type OK struct{}

// Secret carries a fetched secret value.
type Secret struct {
	Value   []byte
	Version uint64
}

// Version is the new version after a successful write.
type Version struct{ Version uint64 }

// VersionConflict is a failed compare-and-set precondition.
type VersionConflict struct{ Current uint64 }

// Names lists secrets in a group.
type Names []NameVersion

// Identities lists registered identities.
type Identities []IdentityInfo

// Groups lists the groups visible to the caller.
type Groups struct {
	ServiceAdmin bool
	Groups       []GroupInfo
}

// ACL lists a group's access control entries.
type ACL []ACLEntry

// IdentityNames lists the names of all registered identities (no endpoint
// ids or service-admin flags).
type IdentityNames []string

// Failed is a post-authorization failure with an informative reason.
type Failed struct{ Reason string }

func (Denied) isResponse()          {}
func (OK) isResponse()              {}
func (Secret) isResponse()          {}
func (Version) isResponse()         {}
func (VersionConflict) isResponse() {}
func (Names) isResponse()           {}
func (Identities) isResponse()      {}
func (Groups) isResponse()          {}
func (ACL) isResponse()             {}
func (IdentityNames) isResponse()   {}
func (Failed) isResponse()          {}

func decodeResponse(buf []byte) (Response, error) {
	// Unit variants arrive as bare text strings.
	var unit string
	if err := cbor.Unmarshal(buf, &unit); err == nil {
		switch unit {
		case "Denied":
			return Denied{}, nil
		case "Ok":
			return OK{}, nil
		default:
			return nil, fmt.Errorf("unknown response variant %q", unit)
		}
	}
	// Everything else is a single-entry map keyed by the variant name.
	var envelope map[string]cbor.RawMessage
	if err := cbor.Unmarshal(buf, &envelope); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	if len(envelope) != 1 {
		return nil, errors.New("response envelope must have exactly one entry")
	}
	for variant, raw := range envelope {
		switch variant {
		case "Secret":
			var body struct {
				Value   []byte `cbor:"value"`
				Version uint64 `cbor:"version"`
			}
			if err := cbor.Unmarshal(raw, &body); err != nil {
				return nil, err
			}
			return Secret{Value: body.Value, Version: body.Version}, nil
		case "Version":
			var body struct {
				Version uint64 `cbor:"version"`
			}
			if err := cbor.Unmarshal(raw, &body); err != nil {
				return nil, err
			}
			return Version{Version: body.Version}, nil
		case "VersionConflict":
			var body struct {
				Current uint64 `cbor:"current"`
			}
			if err := cbor.Unmarshal(raw, &body); err != nil {
				return nil, err
			}
			return VersionConflict{Current: body.Current}, nil
		case "Names":
			var names Names
			if err := cbor.Unmarshal(raw, &names); err != nil {
				return nil, err
			}
			return names, nil
		case "Identities":
			var ids Identities
			if err := cbor.Unmarshal(raw, &ids); err != nil {
				return nil, err
			}
			return ids, nil
		case "Groups":
			var body struct {
				ServiceAdmin bool        `cbor:"service_admin"`
				Groups       []GroupInfo `cbor:"groups"`
			}
			if err := cbor.Unmarshal(raw, &body); err != nil {
				return nil, err
			}
			return Groups{ServiceAdmin: body.ServiceAdmin, Groups: body.Groups}, nil
		case "Acl":
			var acl ACL
			if err := cbor.Unmarshal(raw, &acl); err != nil {
				return nil, err
			}
			return acl, nil
		case "IdentityNames":
			var names IdentityNames
			if err := cbor.Unmarshal(raw, &names); err != nil {
				return nil, err
			}
			return names, nil
		case "Failed":
			var body struct {
				Reason string `cbor:"reason"`
			}
			if err := cbor.Unmarshal(raw, &body); err != nil {
				return nil, err
			}
			return Failed{Reason: body.Reason}, nil
		default:
			return nil, fmt.Errorf("unknown response variant %q", variant)
		}
	}
	return nil, errors.New("unreachable: empty envelope")
}
