package secretbunker

// Tests of Dial that need no server binary. The two that dial by id use
// the network when there is one (n0's DNS and pkarr relay, mDNS on the
// local links) and must fail the same way when there is none.

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
)

// unannouncedID is the id of a key generated on the spot: nobody
// announces it anywhere.
func unannouncedID(t *testing.T) string {
	t.Helper()
	other, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	return other.Public().EndpointID().String()
}

// goroutineStacks returns the stacks of all goroutines.
func goroutineStacks() string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

// goroutines returns the stack of every goroutine, keyed by its header up
// to the state ("goroutine 12"), which names it for as long as it runs.
func goroutines() map[string]string {
	running := make(map[string]string)
	for stack := range strings.SplitSeq(goroutineStacks(), "\n\n") {
		name, _, _ := strings.Cut(stack, " [")
		running[name] = stack
	}
	return running
}

// startedSince returns the stacks of the goroutines that run now and did
// not when before was taken.
func startedSince(before map[string]string) []string {
	var started []string
	for name, stack := range goroutines() {
		if _, ok := before[name]; !ok {
			started = append(started, stack)
		}
	}
	return started
}

// within returns the stacks that have a frame in the package or module
// path.
func within(stacks []string, path string) []string {
	var found []string
	for _, stack := range stacks {
		if strings.Contains(stack, path) {
			found = append(found, stack)
		}
	}
	return found
}

// mdnsGoroutines returns the stacks of the goroutines running go-iroh's
// mDNS discovery: its listener and what it starts.
func mdnsGoroutines() []string {
	return within(startedSince(nil), "go-iroh/iroh/mdns.")
}

func TestDialUnknownIDFailsWithinDeadline(t *testing.T) {
	secret, _ := key.GenerateSecretKey()
	other, _ := key.GenerateSecretKey()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err := Dial(ctx, secret, other.Public().EndpointID().String())
	if err == nil {
		t.Fatal("dialing an id nobody announces succeeded")
	}
	if strings.Contains(err.Error(), "at least one server address") {
		t.Fatalf("Dial still refuses to dial by id: %v", err)
	}
	if took := time.Since(start); took > 8*time.Second {
		t.Fatalf("Dial took %s, past its 5s deadline", took)
	}
	// A reader must be able to tell a failed discovery from a failed
	// direct dial, and which bunker was not found.
	want := "connecting to bunker " + other.Public().EndpointID().String()[:8] + " by discovery: "
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err, want)
	}
}

func TestFailedDialLeavesNothingRunning(t *testing.T) {
	secret, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := unannouncedID(t)
	before := goroutines()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = Dial(ctx, secret, id)
	if err == nil {
		t.Fatal("dialing an id nobody announces succeeded")
	}
	// Without this the test passes for a Dial that never started anything.
	if strings.Contains(err.Error(), "at least one server address") {
		t.Fatalf("Dial still refuses to dial by id: %v", err)
	}

	// The endpoint is shut down and the mDNS listener stopped: nothing of
	// go-iroh's runs once they have wound down.
	deadline := time.Now().Add(5 * time.Second)
	for {
		left := within(startedSince(before), "github.com/tmc/go-iroh/")
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a failed Dial left %d goroutines of go-iroh running:\n%s", len(left), strings.Join(left, "\n\n"))
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Nothing else runs either, up to 2 goroutines for the runtime's own.
	// This takes longer than the 5s above when n0's servers are reachable:
	// go-iroh v0.3.0 leaves the HTTP connections of its net report probes
	// (one transport per probe, never closed) and of the pkarr lookup (in
	// http.DefaultTransport) idle, each with a read and a write goroutine,
	// until the server closes them about 30s later. No shutdown reaches
	// them, so the wait is for the servers.
	deadline = time.Now().Add(60 * time.Second)
	for {
		left := startedSince(before)
		if len(left) <= 2 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("a failed Dial left %d goroutines running:\n%s", len(left), strings.Join(left, "\n\n"))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDialRefusesAHostnameBeforeAnyNetworkUse(t *testing.T) {
	secret, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := unannouncedID(t)
	before := goroutines()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, secret, id, "bunker.example:4433")
	if err == nil {
		_ = client.Close(context.Background())
		t.Fatal("Dial accepted a hostname as a server address")
	}
	if want := `parsing server address "bunker.example:4433"`; !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err, want)
	}
	// Binding an endpoint starts goroutines; a refusal before any network
	// use starts none.
	if started := startedSince(before); len(started) > 0 {
		t.Fatalf("Dial started %d goroutines before refusing the address:\n%s",
			len(started), strings.Join(started, "\n\n"))
	}
}
