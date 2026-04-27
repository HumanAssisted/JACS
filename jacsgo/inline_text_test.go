// Inline text sign/verify tests (Task 12 — PRD §3.1, §4.1, C1, C2).
//
// Pure-stdlib (no extra deps). The Go binding routes through the new CGo FFI
// exports added in jacsgo/lib/src/lib.rs. Each test creates an ephemeral
// SimpleAgent, writes a temp file, and exercises the SignText/VerifyText
// surface end-to-end.

package jacs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func strPtr(s string) *string { return &s }

func TestSignTextRoundTrip(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "r.md")
	if err := os.WriteFile(target, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	if err := agent.SignText(target, nil); err != nil {
		t.Fatalf("SignText: %v", err)
	}

	result, err := agent.VerifyText(target, nil)
	if err != nil {
		t.Fatalf("VerifyText: %v", err)
	}
	if result.Status != "signed" {
		t.Fatalf("expected status=signed, got %q", result.Status)
	}
	if len(result.Signatures) != 1 {
		t.Fatalf("expected exactly 1 signature, got %d", len(result.Signatures))
	}
}

// C2: content bytes preserved; no -----BEGIN JACS SIGNED MESSAGE----- wrapper.
func TestSignTextContentPreserved(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "c2.md")
	original := "# Title\n\nHello\n"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	if err := agent.SignText(target, nil); err != nil {
		t.Fatalf("SignText: %v", err)
	}

	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "-----BEGIN JACS SIGNED MESSAGE-----") {
		t.Fatal("C2 violation: PGP-style wrapper found in signed output")
	}
	markerIdx := strings.Index(string(content), "-----BEGIN JACS SIGNATURE-----")
	if markerIdx < 0 {
		t.Fatal("no signature marker found in signed output")
	}
	prefix := strings.TrimRight(string(content[:markerIdx]), "\n") + "\n"
	if prefix != original {
		t.Fatalf("C2 violation: content prefix mutated\nwant: %q\ngot:  %q", original, prefix)
	}
}

// C1 permissive: missing-signature returns a typed status, no error.
func TestVerifyTextPermissiveMissingSignatureIsNotError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "plain.md")
	if err := os.WriteFile(target, []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	result, err := agent.VerifyText(target, nil)
	if err != nil {
		t.Fatalf("VerifyText permissive must not return an error for missing signature, got %v", err)
	}
	if result.Status != "missing_signature" {
		t.Fatalf("expected missing_signature, got %q", result.Status)
	}
}

// C1 strict: missing-signature returns an error wrapping ErrMissingSignature.
func TestVerifyTextStrictMissingSignatureIsError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "plain2.md")
	if err := os.WriteFile(target, []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	_, err = agent.VerifyText(target, &VerifyTextOpts{Strict: true})
	if err == nil {
		t.Fatal("expected an error for strict-missing-signature, got nil")
	}
	if !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected errors.Is(err, ErrMissingSignature), got %v", err)
	}
}

// C1 strict on a valid file returns normally.
func TestVerifyTextStrictValidIsOk(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "ok.md")
	if err := os.WriteFile(target, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	if err := agent.SignText(target, nil); err != nil {
		t.Fatal(err)
	}

	result, err := agent.VerifyText(target, &VerifyTextOpts{Strict: true})
	if err != nil {
		t.Fatalf("VerifyText strict valid: %v", err)
	}
	if result.Status != "signed" {
		t.Fatalf("expected status=signed, got %q", result.Status)
	}
}

// pq2025 sign + verify round trip.
func TestSignVerifyTextPq2025(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "pq.md")
	if err := os.WriteFile(target, []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	agent, _, err := EphemeralSimpleAgent(strPtr("pq2025"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	if err := agent.SignText(target, nil); err != nil {
		t.Fatal(err)
	}

	result, err := agent.VerifyText(target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "signed" {
		t.Fatalf("expected status=signed, got %q", result.Status)
	}
	if len(result.Signatures) == 0 || result.Signatures[0].Algorithm != "pq2025" {
		t.Fatalf("expected pq2025 signature, got %+v", result.Signatures)
	}
}

// Duplicate-signer call is a byte-identical no-op at the binding layer.
func TestSignTextDuplicateIsNoOp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dup.md")
	if err := os.WriteFile(target, []byte("same\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	if err := agent.SignText(target, nil); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(target)

	if err := agent.SignText(target, nil); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(target)

	if !bytes.Equal(first, second) {
		t.Fatalf("duplicate SignText must be byte-identical (first=%d bytes, second=%d bytes)",
			len(first), len(second))
	}
	if got := strings.Count(string(second), "-----BEGIN JACS SIGNATURE-----"); got != 1 {
		t.Fatalf("expected exactly 1 signature block after duplicate SignText, got %d", got)
	}
}

// Parity-name SignTextFile / VerifyTextFile work alongside the short aliases.
func TestSignTextFileParityName(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "parity.md")
	if err := os.WriteFile(target, []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	if err := agent.SignTextFile(target, nil); err != nil {
		t.Fatalf("SignTextFile: %v", err)
	}

	result, err := agent.VerifyTextFile(target, nil)
	if err != nil {
		t.Fatalf("VerifyTextFile: %v", err)
	}
	if result.Status != "signed" {
		t.Fatalf("expected status=signed, got %q", result.Status)
	}
}
