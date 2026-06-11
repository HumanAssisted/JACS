package jacs

import (
	"sync"
	"testing"
)

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
