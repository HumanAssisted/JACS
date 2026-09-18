package jacs

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

const copiedHandleHelperEnv = "JACSGO_COPIED_HANDLE_HELPER"

// TestCopiedHandlesShareCloseState runs the unsafe copy/close sequence in a
// subprocess because the historical implementation copied a raw native
// handle and its mutex independently. Closing both copies could therefore
// double-free the Rust allocation and abort the entire Go test process.
func TestCopiedHandlesShareCloseState(t *testing.T) {
	skipIfLibraryMissing(t)

	for _, kind := range []string{"agent", "simple"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCopiedHandleHelper$")
			cmd.Env = append(os.Environ(), copiedHandleHelperEnv+"="+kind)
			output, err := cmd.CombinedOutput()
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatalf("copied %s handle subprocess exceeded 15-second deadlock deadline\n%s", kind, output)
			}
			if err != nil {
				t.Fatalf("copied %s handle subprocess failed: %v\n%s", kind, err, output)
			}
		})
	}
}

// TestCopiedHandleHelper is selected by TestCopiedHandlesShareCloseState in a
// subprocess. It intentionally copies each public wrapper by value, closes
// both copies concurrently, and verifies that either close invalidates both
// views without a crash, race, use-after-free, or double-free.
func TestCopiedHandleHelper(t *testing.T) {
	kind := os.Getenv(copiedHandleHelperEnv)
	if kind == "" {
		t.Skip("subprocess helper")
	}

	switch kind {
	case "agent":
		original, err := NewJacsAgent()
		if err != nil {
			t.Fatalf("NewJacsAgent: %v", err)
		}
		copied := *original
		closeCopiedAgentsConcurrently(original, &copied)
		if _, err := original.SignString("closed"); !errors.Is(err, errAgentClosed) {
			t.Fatalf("original SignString error = %v, want %v", err, errAgentClosed)
		}
		if _, err := copied.SignString("closed"); !errors.Is(err, errAgentClosed) {
			t.Fatalf("copied SignString error = %v, want %v", err, errAgentClosed)
		}
	case "simple":
		algo := "ed25519"
		original, _, err := EphemeralSimpleAgent(&algo)
		if err != nil {
			t.Fatalf("EphemeralSimpleAgent: %v", err)
		}
		copied := *original
		closeCopiedSimpleAgentsConcurrently(original, &copied)
		if _, err := original.GetAgentID(); !errors.Is(err, errSimpleAgentClosed) {
			t.Fatalf("original GetAgentID error = %v, want %v", err, errSimpleAgentClosed)
		}
		if _, err := copied.GetAgentID(); !errors.Is(err, errSimpleAgentClosed) {
			t.Fatalf("copied GetAgentID error = %v, want %v", err, errSimpleAgentClosed)
		}
	default:
		t.Fatalf("unknown helper kind %q", kind)
	}
}

func closeCopiedAgentsConcurrently(first, second *JacsAgent) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		first.Close()
	}()
	go func() {
		defer wg.Done()
		<-start
		second.Close()
	}()
	close(start)
	wg.Wait()
}

func closeCopiedSimpleAgentsConcurrently(first, second *JacsSimpleAgent) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		first.Close()
	}()
	go func() {
		defer wg.Done()
		<-start
		second.Close()
	}()
	close(start)
	wg.Wait()
}

// TestCloseRaceSimpleAgent exercises Close() concurrently with in-flight method
// calls on the same JacsSimpleAgent handle. Under -race, an unguarded Close()
// (freeing the handle while a method reads it) is a use-after-free / data race.
// With the RWMutex guard, Close() cannot free a handle a method is using and
// post-Close calls return a clean "is closed" error instead of crashing.
func TestCloseRaceSimpleAgent(t *testing.T) {
	skipIfLibraryMissing(t)
	algo := "ed25519"
	agent, _, err := EphemeralSimpleAgent(&algo)
	if err != nil {
		t.Fatalf("EphemeralSimpleAgent: %v", err)
	}

	var wg sync.WaitGroup
	const workers = 8
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				// Method calls may succeed or return "is closed" after Close;
				// neither may crash or race.
				_, _ = agent.GetAgentID()
				_ = agent.IsStrict()
				_, _ = agent.VerifySelf()
			}
		}()
	}

	// Close concurrently with the in-flight workers.
	closer := make(chan struct{})
	go func() {
		<-closer
		agent.Close()
	}()
	close(closer)

	wg.Wait()
	// Drain Close goroutine completion by closing again (idempotent under lock).
	agent.Close()

	// Post-close call must return an error, not crash.
	if _, err := agent.GetAgentID(); err == nil {
		t.Fatal("expected error after Close(), got nil")
	}
}

// TestCloseRaceJacsAgent does the same for the handle-based JacsAgent type.
func TestCloseRaceJacsAgent(t *testing.T) {
	skipIfLibraryMissing(t)
	agent, err := NewJacsAgent()
	if err != nil {
		t.Fatalf("NewJacsAgent: %v", err)
	}

	var wg sync.WaitGroup
	const workers = 8
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = agent.SignString("hello")
				_, _ = agent.GetJSON()
			}
		}()
	}

	closer := make(chan struct{})
	go func() {
		<-closer
		agent.Close()
	}()
	close(closer)

	wg.Wait()
	agent.Close()

	if _, err := agent.SignString("hello"); err == nil {
		t.Fatal("expected error after Close(), got nil")
	}
}
