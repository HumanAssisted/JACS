package jacs

import "testing"

// newEphemeralAgent creates an ephemeral SimpleAgent for tests, failing the
// test on error and registering Close via t.Cleanup (runs even if a later
// t.Fatal in the same test unwinds, unlike a bare defer in a helper).
func newEphemeralAgent(t *testing.T, algo string) *JacsSimpleAgent {
	t.Helper()
	agent, _, err := EphemeralSimpleAgent(&algo)
	if err != nil {
		t.Fatalf("EphemeralSimpleAgent(%q): %v", algo, err)
	}
	t.Cleanup(func() { agent.Close() })
	return agent
}
