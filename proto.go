package secretbunker

// Wire types mirroring the Rust server's proto.rs. Variant indices are the
// postcard enum discriminants — a wire contract shared with
// github.com/fables-for-robots/secret-bunker-iroh (see its
// wire_format_is_stable test). Append-only; never renumber.

import (
	"fmt"
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

// Request discriminants.
const (
	reqGet uint64 = iota
	reqPut
	reqDelete
	reqList
	reqCreateGroup
	reqAddIdentity
	reqRemoveIdentity
	reqListIdentities
	reqGrant
	reqRotateDek
	reqListGroups
	reqGroupAcl
)

// Response discriminants.
const (
	respDenied uint64 = iota
	respOk
	respSecret
	respVersion
	respVersionConflict
	respNames
	respIdentities
	respGroups
	respAcl
	respFailed
)

func encodeRequest(discriminant uint64, fields func(*encoder)) []byte {
	e := &encoder{}
	e.uvarint(discriminant)
	if fields != nil {
		fields(e)
	}
	return e.buf
}

func encGet(group, name string) []byte {
	return encodeRequest(reqGet, func(e *encoder) { e.str(group); e.str(name) })
}

func encPut(group, name string, value []byte, expectedVersion uint64) []byte {
	return encodeRequest(reqPut, func(e *encoder) {
		e.str(group)
		e.str(name)
		e.bytes(value)
		e.uvarint(expectedVersion)
	})
}

func encDelete(group, name string, expectedVersion uint64) []byte {
	return encodeRequest(reqDelete, func(e *encoder) {
		e.str(group)
		e.str(name)
		e.uvarint(expectedVersion)
	})
}

func encList(group string) []byte {
	return encodeRequest(reqList, func(e *encoder) { e.str(group) })
}

func encCreateGroup(name string) []byte {
	return encodeRequest(reqCreateGroup, func(e *encoder) { e.str(name) })
}

func encAddIdentity(name, endpointID string, serviceAdmin bool) []byte {
	return encodeRequest(reqAddIdentity, func(e *encoder) {
		e.str(name)
		e.str(endpointID)
		e.boolean(serviceAdmin)
	})
}

func encRemoveIdentity(name string) []byte {
	return encodeRequest(reqRemoveIdentity, func(e *encoder) { e.str(name) })
}

func encListIdentities() []byte {
	return encodeRequest(reqListIdentities, nil)
}

func encGrant(group, identity string, perms byte) []byte {
	return encodeRequest(reqGrant, func(e *encoder) {
		e.str(group)
		e.str(identity)
		e.u8(perms)
	})
}

func encRotateDek(group string) []byte {
	return encodeRequest(reqRotateDek, func(e *encoder) { e.str(group) })
}

func encListGroups() []byte {
	return encodeRequest(reqListGroups, nil)
}

func encGroupAcl(group string) []byte {
	return encodeRequest(reqGroupAcl, func(e *encoder) { e.str(group) })
}

// NameVersion is one entry of a secret listing.
type NameVersion struct {
	Name    string
	Version uint64
}

// IdentityInfo describes a registered identity.
type IdentityInfo struct {
	Name         string
	EndpointID   string
	ServiceAdmin bool
}

// GroupInfo is one entry of a group listing, with the caller's own
// permission bitmask on that group.
type GroupInfo struct {
	Name  string
	Perms byte
}

// ACLEntry is one identity's permissions on a group.
type ACLEntry struct {
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

// Failed is an post-authorization failure with an informative reason.
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
func (Failed) isResponse()          {}

func decodeResponse(buf []byte) (Response, error) {
	d := &decoder{buf: buf}
	discriminant, err := d.uvarint()
	if err != nil {
		return nil, err
	}
	var resp Response
	switch discriminant {
	case respDenied:
		resp = Denied{}
	case respOk:
		resp = OK{}
	case respSecret:
		var s Secret
		if s.Value, err = d.bytes(); err != nil {
			return nil, err
		}
		if s.Version, err = d.uvarint(); err != nil {
			return nil, err
		}
		resp = s
	case respVersion:
		var v Version
		if v.Version, err = d.uvarint(); err != nil {
			return nil, err
		}
		resp = v
	case respVersionConflict:
		var v VersionConflict
		if v.Current, err = d.uvarint(); err != nil {
			return nil, err
		}
		resp = v
	case respNames:
		count, err := d.uvarint()
		if err != nil {
			return nil, err
		}
		names := make(Names, 0, count)
		for range count {
			var nv NameVersion
			if nv.Name, err = d.str(); err != nil {
				return nil, err
			}
			if nv.Version, err = d.uvarint(); err != nil {
				return nil, err
			}
			names = append(names, nv)
		}
		resp = names
	case respIdentities:
		count, err := d.uvarint()
		if err != nil {
			return nil, err
		}
		ids := make(Identities, 0, count)
		for range count {
			var info IdentityInfo
			if info.Name, err = d.str(); err != nil {
				return nil, err
			}
			if info.EndpointID, err = d.str(); err != nil {
				return nil, err
			}
			if info.ServiceAdmin, err = d.boolean(); err != nil {
				return nil, err
			}
			ids = append(ids, info)
		}
		resp = ids
	case respGroups:
		var g Groups
		if g.ServiceAdmin, err = d.boolean(); err != nil {
			return nil, err
		}
		count, err := d.uvarint()
		if err != nil {
			return nil, err
		}
		g.Groups = make([]GroupInfo, 0, count)
		for range count {
			var info GroupInfo
			if info.Name, err = d.str(); err != nil {
				return nil, err
			}
			if info.Perms, err = d.u8(); err != nil {
				return nil, err
			}
			g.Groups = append(g.Groups, info)
		}
		resp = g
	case respAcl:
		count, err := d.uvarint()
		if err != nil {
			return nil, err
		}
		acl := make(ACL, 0, count)
		for range count {
			var entry ACLEntry
			if entry.Identity, err = d.str(); err != nil {
				return nil, err
			}
			if entry.Perms, err = d.u8(); err != nil {
				return nil, err
			}
			acl = append(acl, entry)
		}
		resp = acl
	case respFailed:
		var f Failed
		if f.Reason, err = d.str(); err != nil {
			return nil, err
		}
		resp = f
	default:
		return nil, fmt.Errorf("unknown response discriminant %d", discriminant)
	}
	if err := d.done(); err != nil {
		return nil, err
	}
	return resp, nil
}
