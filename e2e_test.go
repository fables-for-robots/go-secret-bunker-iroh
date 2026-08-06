package secretbunker

// Cross-language end-to-end test: this Go client against the real Rust
// secret-bunker-iroh server. Set SECRET_BUNKER_BIN to the server binary
// (the test is skipped without it):
//
//	SECRET_BUNKER_BIN=../secret-bunker-iroh/target/debug/secret-bunker-iroh go test ./...

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
)

type bunkerServer struct {
	id   string
	addr string
}

// startServer initializes a bunker database with adminID as the service
// admin and runs `serve --no-relay --no-mdns`, returning its EndpointId
// and direct socket address.
func startServer(t *testing.T, bin, adminID string) bunkerServer {
	t.Helper()
	dir := t.TempDir()
	xdg := filepath.Join(dir, "xdg-server")
	db := filepath.Join(dir, "bunker.sqlite")

	run := func(args ...string) string {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+xdg)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", bin, args, err, out)
		}
		return strings.TrimSpace(string(out))
	}

	backupPub := run("keygen-age", "--out", filepath.Join(dir, "backup.age"))
	run("init", "--db", db, "--backup-pubkey", backupPub, "--admin-id", adminID)

	logPath := filepath.Join(dir, "serve.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	serve := exec.Command(bin, "serve", "--db", db, "--no-relay", "--no-mdns")
	serve.Env = append(os.Environ(), "XDG_DATA_HOME="+xdg)
	serve.Stderr = logFile
	if err := serve.Start(); err != nil {
		t.Fatalf("starting server: %v", err)
	}
	t.Cleanup(func() {
		_ = serve.Process.Signal(syscall.SIGINT)
		_ = serve.Wait()
		_ = logFile.Close()
	})

	// Wait for the server to log its id and bound port.
	deadline := time.Now().Add(20 * time.Second)
	for {
		var server bunkerServer
		if contents, err := os.ReadFile(logPath); err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(contents)))
			for scanner.Scan() {
				line := scanner.Text()
				if id, ok := strings.CutPrefix(line, "bunker endpoint id: "); ok {
					server.id = id
				}
				if hostPort, ok := strings.CutPrefix(line, "bound: 0.0.0.0:"); ok {
					server.addr = "127.0.0.1:" + hostPort
				}
			}
			if server.id != "" && server.addr != "" {
				return server
			}
		}
		if time.Now().After(deadline) {
			contents, _ := os.ReadFile(logPath)
			t.Fatalf("server did not become ready; log:\n%s", contents)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func generateKey(t *testing.T) key.SecretKey {
	t.Helper()
	secret, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func dial(t *testing.T, ctx context.Context, secret key.SecretKey, server bunkerServer) *Client {
	t.Helper()
	client, err := Dial(ctx, secret, server.id, server.addr)
	if err != nil {
		t.Fatalf("dialing bunker: %v", err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	return client
}

func TestCrossLanguageLifecycle(t *testing.T) {
	bin := os.Getenv("SECRET_BUNKER_BIN")
	if bin == "" {
		t.Skip("SECRET_BUNKER_BIN not set; skipping cross-language e2e")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adminKey := generateKey(t)
	userKey := generateKey(t)
	strangerKey := generateKey(t)
	adminID := key.EndpointID(adminKey.Public()).String()
	userID := key.EndpointID(userKey.Public()).String()

	server := startServer(t, bin, adminID)
	admin := dial(t, ctx, adminKey, server)

	// The Rust server derived the same identity from our Go-generated key.
	if admin.ID() != adminID {
		t.Fatalf("client id mismatch: %s vs %s", admin.ID(), adminID)
	}
	groups, err := admin.ListGroups(ctx)
	if err != nil {
		t.Fatalf("admin ListGroups: %v", err)
	}
	if !groups.ServiceAdmin {
		t.Fatal("admin must be recognized as service admin")
	}

	// Admin: create a group and a secret; read it back byte-for-byte.
	if err := admin.CreateGroup(ctx, "team"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	value := []byte("cross-language \x00 secret \xf0\x9f\x94\x91")
	version, err := admin.Put(ctx, "team", "api-key", value, 0)
	if err != nil || version != 1 {
		t.Fatalf("Put: version %d, err %v", version, err)
	}
	secret, err := admin.Get(ctx, "team", "api-key")
	if err != nil || !reflect.DeepEqual(secret.Value, value) || secret.Version != 1 {
		t.Fatalf("Get: %+v, err %v", secret, err)
	}

	// CAS: a stale write is a conflict carrying the current version.
	var conflict *ConflictError
	if _, err := admin.Put(ctx, "team", "api-key", []byte("x"), 0); !errors.As(err, &conflict) || conflict.Current != 1 {
		t.Fatalf("stale Put: expected ConflictError{1}, got %v", err)
	}

	// Register the user and walk the grant/revoke lifecycle.
	if err := admin.AddIdentity(ctx, "go-user", userID, false); err != nil {
		t.Fatalf("AddIdentity: %v", err)
	}
	user := dial(t, ctx, userKey, server)
	if _, err := user.Get(ctx, "team", "api-key"); !errors.Is(err, ErrDenied) {
		t.Fatalf("ungranted user Get: expected ErrDenied, got %v", err)
	}
	if err := admin.Grant(ctx, "team", "go-user", PermRead|PermWrite); err != nil {
		t.Fatalf("Grant rw: %v", err)
	}
	if version, err = user.Put(ctx, "team", "scratch", []byte("temp"), 0); err != nil || version != 1 {
		t.Fatalf("user Put: version %d, err %v", version, err)
	}
	if err := user.Delete(ctx, "team", "scratch", 1); err != nil {
		t.Fatalf("user Delete: %v", err)
	}
	if _, err := user.Get(ctx, "team", "scratch"); !errors.Is(err, ErrDenied) {
		t.Fatalf("deleted secret must be uniformly denied, got %v", err)
	}

	// Revocation applies to the user's open connection immediately.
	if err := admin.Grant(ctx, "team", "go-user", 0); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := user.Get(ctx, "team", "api-key"); !errors.Is(err, ErrDenied) {
		t.Fatalf("revoked user Get: expected ErrDenied, got %v", err)
	}

	// Read-only: reads work, writes and deletes stay denied.
	if err := admin.Grant(ctx, "team", "go-user", PermRead); err != nil {
		t.Fatalf("grant read-only: %v", err)
	}
	if secret, err = user.Get(ctx, "team", "api-key"); err != nil || !reflect.DeepEqual(secret.Value, value) {
		t.Fatalf("read-only Get: %+v, err %v", secret, err)
	}
	if _, err := user.Put(ctx, "team", "api-key", []byte("nope"), 1); !errors.Is(err, ErrDenied) {
		t.Fatalf("read-only Put: expected ErrDenied, got %v", err)
	}
	if err := user.Delete(ctx, "team", "api-key", 1); !errors.Is(err, ErrDenied) {
		t.Fatalf("read-only Delete: expected ErrDenied, got %v", err)
	}

	// Visibility: the user sees only its group; the ACL matches the grants.
	userGroups, err := user.ListGroups(ctx)
	if err != nil || userGroups.ServiceAdmin {
		t.Fatalf("user ListGroups: %+v, err %v", userGroups, err)
	}
	if want := []GroupInfo{{Name: "team", Perms: PermRead}}; !reflect.DeepEqual(userGroups.Groups, want) {
		t.Fatalf("user groups: %+v, want %+v", userGroups.Groups, want)
	}
	acl, err := admin.GroupACL(ctx, "team")
	if err != nil {
		t.Fatalf("GroupACL: %v", err)
	}
	wantACL := ACL{
		{Identity: "admin", Perms: PermRead | PermWrite | PermAdmin},
		{Identity: "go-user", Perms: PermRead},
	}
	if !reflect.DeepEqual(acl, wantACL) {
		t.Fatalf("ACL: %+v, want %+v", acl, wantACL)
	}

	// Grant targets: identity names are listable by group admins — even
	// ones that are not service admins — and by nobody below that.
	if _, err := user.ListIdentityNames(ctx, "team"); !errors.Is(err, ErrDenied) {
		t.Fatalf("read-only ListIdentityNames: expected ErrDenied, got %v", err)
	}
	if err := admin.Grant(ctx, "team", "go-user", PermRead|PermAdmin); err != nil {
		t.Fatalf("grant admin: %v", err)
	}
	names, err := user.ListIdentityNames(ctx, "team")
	if err != nil || !reflect.DeepEqual(names, IdentityNames{"admin", "go-user"}) {
		t.Fatalf("ListIdentityNames: %+v, err %v", names, err)
	}
	if _, err := user.ListIdentities(ctx); !errors.Is(err, ErrDenied) {
		t.Fatalf("group-admin ListIdentities: expected ErrDenied, got %v", err)
	}
	if err := admin.Grant(ctx, "team", "go-user", PermRead); err != nil {
		t.Fatalf("restore read-only: %v", err)
	}

	// DEK rotation keeps old secrets readable.
	if err := admin.RotateDek(ctx, "team"); err != nil {
		t.Fatalf("RotateDek: %v", err)
	}
	if secret, err = admin.Get(ctx, "team", "api-key"); err != nil || !reflect.DeepEqual(secret.Value, value) {
		t.Fatalf("post-rotation Get: %+v, err %v", secret, err)
	}

	// A stranger can connect but do nothing, and learns nothing.
	stranger := dial(t, ctx, strangerKey, server)
	for name, call := range map[string]func() error{
		"Get":         func() error { _, err := stranger.Get(ctx, "team", "api-key"); return err },
		"Put":         func() error { _, err := stranger.Put(ctx, "team", "x", []byte("x"), 0); return err },
		"List":        func() error { _, err := stranger.List(ctx, "team"); return err },
		"ListGroups":  func() error { _, err := stranger.ListGroups(ctx); return err },
		"CreateGroup": func() error { return stranger.CreateGroup(ctx, "mine") },
		"GroupACL":    func() error { _, err := stranger.GroupACL(ctx, "team"); return err },
		"ListIdentityNames": func() error {
			_, err := stranger.ListIdentityNames(ctx, "team")
			return err
		},
	} {
		if err := call(); !errors.Is(err, ErrDenied) {
			t.Errorf("stranger %s: expected ErrDenied, got %v", name, err)
		}
	}
}

func TestMain(m *testing.M) {
	if bin := os.Getenv("SECRET_BUNKER_BIN"); bin != "" {
		if _, err := os.Stat(bin); err != nil {
			fmt.Fprintf(os.Stderr, "SECRET_BUNKER_BIN=%s: %v\n", bin, err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}
