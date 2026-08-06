// Package secretbunker is a Go client for secret-bunker-iroh: a secrets
// service reached over iroh (peer-to-peer QUIC dialed by public key).
//
// The client's identity is its iroh key; the server authenticates it in
// the transport handshake and authorizes every request against its ACLs.
// There is no application-layer signing and no TLS configuration.
package secretbunker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// ErrDenied is the bunker's uniform denial: unknown identity, missing
// permission, or nonexistent target — deliberately indistinguishable.
var ErrDenied = errors.New("denied by bunker")

// ConflictError reports a failed compare-and-set precondition.
type ConflictError struct{ Current uint64 }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("version conflict: current version is %d", e.Current)
}

// FailedError is a post-authorization failure with the server's reason.
type FailedError struct{ Reason string }

func (e *FailedError) Error() string { return "bunker operation failed: " + e.Reason }

// Client is a connection to one bunker. Safe for concurrent use; each
// request runs on its own stream.
type Client struct {
	endpoint *iroh.Endpoint
	conn     *iroh.Conn
}

// Dial connects to the bunker with the given EndpointId (lowercase hex)
// at one of the given "ip:port" addresses, authenticating as secret.
func Dial(ctx context.Context, secret key.SecretKey, serverID string, addrs ...string) (*Client, error) {
	if len(addrs) == 0 {
		return nil, errors.New("at least one server address is required")
	}
	id, err := key.ParseEndpointID(serverID)
	if err != nil {
		return nil, fmt.Errorf("parsing server id: %w", err)
	}
	addr := netaddr.NewEndpointAddr(id)
	for _, a := range addrs {
		ap, err := netip.ParseAddrPort(a)
		if err != nil {
			return nil, fmt.Errorf("parsing server address %q: %w", a, err)
		}
		addr = addr.WithIP(ap)
	}
	endpoint, err := iroh.Bind(ctx, iroh.WithSecretKey(secret))
	if err != nil {
		return nil, fmt.Errorf("binding iroh endpoint: %w", err)
	}
	conn, err := endpoint.Connect(ctx, addr, ALPN)
	if err != nil {
		_ = endpoint.Shutdown(context.WithoutCancel(ctx))
		return nil, fmt.Errorf("connecting to bunker: %w", err)
	}
	return &Client{endpoint: endpoint, conn: conn}, nil
}

// Close terminates the connection and shuts the endpoint down.
func (c *Client) Close(ctx context.Context) error {
	_ = c.conn.Close()
	return c.endpoint.Shutdown(ctx)
}

// ID is this client's own EndpointId (lowercase hex) — the identity the
// bunker's ACLs see.
func (c *Client) ID() string {
	return c.endpoint.ID().String()
}

// do sends one encoded request on a fresh stream and decodes the reply.
func (c *Client) do(ctx context.Context, req []byte) (Response, error) {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("opening request stream: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	if _, err := stream.Write(req); err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	// Half-close: FIN the send side, then read the response to EOF.
	if err := stream.Close(); err != nil {
		return nil, fmt.Errorf("finishing request stream: %w", err)
	}
	buf, err := io.ReadAll(io.LimitReader(stream, MaxMessage+1))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if len(buf) > MaxMessage {
		return nil, errors.New("response exceeds message size limit")
	}
	return decodeResponse(buf)
}

// mapErr converts Denied/Failed replies into errors; other replies pass
// through for the caller to interpret.
func mapErr(resp Response, err error) (Response, error) {
	if err != nil {
		return nil, err
	}
	switch r := resp.(type) {
	case Denied:
		return nil, ErrDenied
	case Failed:
		return nil, &FailedError{Reason: r.Reason}
	default:
		return resp, nil
	}
}

func unexpected(resp Response) error {
	return fmt.Errorf("unexpected response type %T", resp)
}

// expectOK runs a request whose only success reply is OK.
func (c *Client) expectOK(ctx context.Context, req []byte) error {
	resp, err := mapErr(c.do(ctx, req))
	if err != nil {
		return err
	}
	if _, ok := resp.(OK); !ok {
		return unexpected(resp)
	}
	return nil
}

// Get fetches the current version of a secret.
func (c *Client) Get(ctx context.Context, group, name string) (Secret, error) {
	resp, err := mapErr(c.do(ctx, encGet(group, name)))
	if err != nil {
		return Secret{}, err
	}
	secret, ok := resp.(Secret)
	if !ok {
		return Secret{}, unexpected(resp)
	}
	return secret, nil
}

// Put creates (expectedVersion 0) or updates a secret, returning the new
// version. A stale expectedVersion returns *ConflictError.
func (c *Client) Put(ctx context.Context, group, name string, value []byte, expectedVersion uint64) (uint64, error) {
	resp, err := mapErr(c.do(ctx, encPut(group, name, value, expectedVersion)))
	if err != nil {
		return 0, err
	}
	switch r := resp.(type) {
	case Version:
		return r.Version, nil
	case VersionConflict:
		return 0, &ConflictError{Current: r.Current}
	default:
		return 0, unexpected(resp)
	}
}

// Delete removes a secret; expectedVersion must match its current version.
func (c *Client) Delete(ctx context.Context, group, name string, expectedVersion uint64) error {
	resp, err := mapErr(c.do(ctx, encDelete(group, name, expectedVersion)))
	if err != nil {
		return err
	}
	switch r := resp.(type) {
	case OK:
		return nil
	case VersionConflict:
		return &ConflictError{Current: r.Current}
	default:
		return unexpected(resp)
	}
}

// List returns the secrets in a group.
func (c *Client) List(ctx context.Context, group string) (Names, error) {
	resp, err := mapErr(c.do(ctx, encList(group)))
	if err != nil {
		return nil, err
	}
	names, ok := resp.(Names)
	if !ok {
		return nil, unexpected(resp)
	}
	return names, nil
}

// ListGroups returns the caller's role and the groups it can see.
func (c *Client) ListGroups(ctx context.Context) (Groups, error) {
	resp, err := mapErr(c.do(ctx, encListGroups()))
	if err != nil {
		return Groups{}, err
	}
	groups, ok := resp.(Groups)
	if !ok {
		return Groups{}, unexpected(resp)
	}
	return groups, nil
}

// GroupACL returns a group's ACL; requires admin on the group.
func (c *Client) GroupACL(ctx context.Context, group string) (ACL, error) {
	resp, err := mapErr(c.do(ctx, encGroupAcl(group)))
	if err != nil {
		return nil, err
	}
	acl, ok := resp.(ACL)
	if !ok {
		return nil, unexpected(resp)
	}
	return acl, nil
}

// CreateGroup creates a group; requires service admin. The creator is
// granted read|write|admin on the new group.
func (c *Client) CreateGroup(ctx context.Context, name string) error {
	return c.expectOK(ctx, encCreateGroup(name))
}

// AddIdentity registers an EndpointId (lowercase hex) under a name;
// requires service admin.
func (c *Client) AddIdentity(ctx context.Context, name, endpointID string, serviceAdmin bool) error {
	return c.expectOK(ctx, encAddIdentity(name, endpointID, serviceAdmin))
}

// RemoveIdentity deletes a registered identity and all its grants;
// requires service admin.
func (c *Client) RemoveIdentity(ctx context.Context, name string) error {
	return c.expectOK(ctx, encRemoveIdentity(name))
}

// ListIdentities lists registered identities; requires service admin.
func (c *Client) ListIdentities(ctx context.Context) (Identities, error) {
	resp, err := mapErr(c.do(ctx, encListIdentities()))
	if err != nil {
		return nil, err
	}
	ids, ok := resp.(Identities)
	if !ok {
		return nil, unexpected(resp)
	}
	return ids, nil
}

// ListIdentityNames lists the names of all registered identities so grant
// targets can be chosen; requires admin on the group. Unlike
// ListIdentities it needs no service admin and exposes names only.
func (c *Client) ListIdentityNames(ctx context.Context, group string) (IdentityNames, error) {
	resp, err := mapErr(c.do(ctx, encListIdentityNames(group)))
	if err != nil {
		return nil, err
	}
	names, ok := resp.(IdentityNames)
	if !ok {
		return nil, unexpected(resp)
	}
	return names, nil
}

// Grant sets an identity's permission bitmask on a group (0 revokes);
// requires admin on the group.
func (c *Client) Grant(ctx context.Context, group, identity string, perms byte) error {
	return c.expectOK(ctx, encGrant(group, identity, perms))
}

// RotateDek rotates a group's data-encryption key; requires admin on the
// group.
func (c *Client) RotateDek(ctx context.Context, group string) error {
	return c.expectOK(ctx, encRotateDek(group))
}
