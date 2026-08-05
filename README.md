# go-secret-bunker-iroh

Go client for [secret-bunker-iroh](https://github.com/fables-for-robots/secret-bunker-iroh):
a secrets service reached over [iroh](https://www.iroh.computer) — peer-to-peer
QUIC dialed by public key. Pure Go (no CGO), using the native Go iroh
implementation [go-iroh](https://github.com/tmc/go-iroh) via the
[draganm fork](https://github.com/draganm/go-iroh).

The client's identity is its iroh ed25519 key: the server authenticates it
in the QUIC/TLS handshake and authorizes every request against its ACLs.
No certificates, no tokens, no application-layer signing.

## Usage

```go
import (
    "context"

    secretbunker "github.com/fables-for-robots/go-secret-bunker-iroh"
    "github.com/tmc/go-iroh/key"
)

func example(ctx context.Context) error {
    secret, err := key.GenerateSecretKey() // or key.NewSecretKey(seed)
    if err != nil {
        return err
    }
    // Register key.EndpointID(secret.Public()).String() with the bunker's
    // admin, then:
    client, err := secretbunker.Dial(ctx, secret, serverHexID, "192.0.2.10:4433")
    if err != nil {
        return err
    }
    defer client.Close(context.Background())

    if _, err := client.Put(ctx, "prod", "db-password", []byte("hunter2"), 0); err != nil {
        return err
    }
    got, err := client.Get(ctx, "prod", "db-password")
    if err != nil {
        return err // errors.Is(err, secretbunker.ErrDenied), *ConflictError, *FailedError
    }
    _ = got.Value
    return nil
}
```

The full protocol is covered: `Get`, `Put`, `Delete` (compare-and-set
versioning), `List`, `ListGroups`, `GroupACL`, and the admin operations
(`CreateGroup`, `AddIdentity`, `RemoveIdentity`, `ListIdentities`,
`Grant`, `RotateDek`). The bunker's uniform denial surfaces as
`ErrDenied`; CAS failures as `*ConflictError` with the current version.

Because the upstream `go-iroh` module path is `github.com/tmc/go-iroh`,
this module carries a `replace` directive pointing at the
`draganm/go-iroh` fork — consumers inherit the import path, and their own
`go.mod` needs the same replace directive.

## Wire format

Messages are CBOR-encoded in serde's externally-tagged enum representation
(unit variants as text strings, others as single-entry maps keyed by the
variant name), matching the Rust server's `proto.rs` name-for-name. The
encoding lives in `proto.go` (via `fxamacker/cbor`) and is pinned by golden
vectors shared with the Rust test suite (`proto_test.go` here,
`wire_format_is_stable` there) — variant and field names are the wire
contract; never rename them. The full protocol spec with annotated CBOR
examples lives in the server repo:
[docs/protocol.md](https://github.com/fables-for-robots/secret-bunker-iroh/blob/main/docs/protocol.md).

## Testing

Unit tests run standalone. The cross-language end-to-end test drives this
client against the real Rust server (the same suite runs in CI):

```sh
cargo build --manifest-path ../secret-bunker-iroh/Cargo.toml
SECRET_BUNKER_BIN=../secret-bunker-iroh/target/debug/secret-bunker-iroh go test ./...
```

## License

[AGPL-3.0-or-later](LICENSE).
