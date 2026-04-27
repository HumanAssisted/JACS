// Cross-language provenance tests (Task 13, PRD §5.1 / §5.2).
//
// Verifies that text + image fixtures signed by Rust under
// jacs/tests/fixtures/provenance/ are accepted by the Go binding, and that
// a Go-signed file round-trips through the Rust `jacs verify-text` CLI.
//
// Fixtures are committed; regenerate with:
//
//   UPDATE_PROVENANCE_FIXTURES=1 cargo test -p jacs --test \
//     provenance_cross_language_tests -- --ignored regenerate_provenance_fixtures
//
// The whole file is skipped when fixtures are absent.

package jacs

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// fixturesDir resolves the absolute path to jacs/tests/fixtures/provenance/
// from the test package directory using runtime.Caller (more robust than the
// cwd, which varies across IDEs/CI).
func provenanceFixturesDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// jacsgo/cross_language_provenance_test.go → JACS/jacsgo → JACS → jacs/tests/fixtures/provenance
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "jacs", "tests", "fixtures", "provenance"))
}

func provenanceKeysDir(t *testing.T) string {
	return filepath.Join(provenanceFixturesDir(t), "keys")
}

type provenanceMetadata struct {
	Schema       string `json:"schema"`
	GeneratedBy  string `json:"generated_by"`
	JacsVersion  string `json:"jacs_version"`
	AgentEd25519 struct {
		AgentID            string `json:"agent_id"`
		Algorithm          string `json:"algorithm"`
		PublicKeyFilename  string `json:"public_key_filename"`
	} `json:"agent_ed25519"`
	AgentPq2025 struct {
		AgentID            string `json:"agent_id"`
		Algorithm          string `json:"algorithm"`
		PublicKeyFilename  string `json:"public_key_filename"`
	} `json:"agent_pq2025"`
}

func loadProvenanceMetadata(t *testing.T) provenanceMetadata {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(provenanceFixturesDir(t), "metadata.json"))
	if err != nil {
		t.Fatalf("read metadata.json: %v", err)
	}
	var m provenanceMetadata
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse metadata.json: %v", err)
	}
	return m
}

// skipIfFixturesMissing skips the test if the committed fixture set is not
// materialised on disk. Other bindings ship a comparable skip; CI runs the
// regenerate step first when needed.
func skipIfFixturesMissing(t *testing.T) {
	t.Helper()
	meta := filepath.Join(provenanceFixturesDir(t), "metadata.json")
	keys := provenanceKeysDir(t)
	if _, err := os.Stat(meta); errors.Is(err, os.ErrNotExist) {
		t.Skip("provenance fixtures not generated; run UPDATE_PROVENANCE_FIXTURES=1 cargo test ...")
	}
	if _, err := os.Stat(keys); errors.Is(err, os.ErrNotExist) {
		t.Skip("provenance keys directory missing")
	}
}

// ---------------------------------------------------------------------------
// Acceptance #2 — Go verifies all four Rust-signed media types.
// ---------------------------------------------------------------------------

func TestProvenanceVerifyRustSignedEd25519Markdown(t *testing.T) {
	skipIfFixturesMissing(t)
	meta := loadProvenanceMetadata(t)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	target := filepath.Join(provenanceFixturesDir(t), "rust_signed_ed25519.md")
	result, err := agent.VerifyText(target, &VerifyTextOpts{KeyDir: provenanceKeysDir(t)})
	if err != nil {
		t.Fatalf("VerifyText: %v", err)
	}
	if result.Status != "signed" {
		t.Fatalf("status=%q, want signed", result.Status)
	}
	if len(result.Signatures) != 1 {
		t.Fatalf("got %d sigs, want 1", len(result.Signatures))
	}
	sig := result.Signatures[0]
	if sig.Status != "valid" {
		t.Fatalf("sig status=%q, want valid", sig.Status)
	}
	if sig.Algorithm != "ed25519" {
		t.Fatalf("algorithm=%q, want ed25519", sig.Algorithm)
	}
	if sig.SignerID != meta.AgentEd25519.AgentID {
		t.Fatalf("signer_id=%q, want %q", sig.SignerID, meta.AgentEd25519.AgentID)
	}
}

func TestProvenanceVerifyRustSignedPq2025Markdown(t *testing.T) {
	skipIfFixturesMissing(t)
	meta := loadProvenanceMetadata(t)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	target := filepath.Join(provenanceFixturesDir(t), "rust_signed_pq2025.md")
	result, err := agent.VerifyText(target, &VerifyTextOpts{KeyDir: provenanceKeysDir(t)})
	if err != nil {
		t.Fatalf("VerifyText: %v", err)
	}
	if result.Status != "signed" {
		t.Fatalf("status=%q, want signed", result.Status)
	}
	if len(result.Signatures) != 1 {
		t.Fatalf("got %d sigs, want 1", len(result.Signatures))
	}
	sig := result.Signatures[0]
	if sig.Status != "valid" {
		t.Fatalf("sig status=%q, want valid", sig.Status)
	}
	if sig.Algorithm != "pq2025" {
		t.Fatalf("algorithm=%q, want pq2025", sig.Algorithm)
	}
	if sig.SignerID != meta.AgentPq2025.AgentID {
		t.Fatalf("signer_id=%q, want %q", sig.SignerID, meta.AgentPq2025.AgentID)
	}
}

func TestProvenanceVerifyRustSignedMultiAlgo(t *testing.T) {
	skipIfFixturesMissing(t)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	target := filepath.Join(provenanceFixturesDir(t), "rust_signed_multi_algo.md")
	result, err := agent.VerifyText(target, &VerifyTextOpts{KeyDir: provenanceKeysDir(t)})
	if err != nil {
		t.Fatalf("VerifyText: %v", err)
	}
	if result.Status != "signed" {
		t.Fatalf("status=%q, want signed", result.Status)
	}
	if len(result.Signatures) != 2 {
		t.Fatalf("got %d sigs, want 2", len(result.Signatures))
	}
	algos := []string{result.Signatures[0].Algorithm, result.Signatures[1].Algorithm}
	if (algos[0] != "ed25519" && algos[0] != "pq2025") ||
		(algos[1] != "ed25519" && algos[1] != "pq2025") ||
		algos[0] == algos[1] {
		t.Fatalf("expected one ed25519 and one pq2025; got %v", algos)
	}
	for _, sig := range result.Signatures {
		if sig.Status != "valid" {
			t.Fatalf("sig %v status=%q, want valid", sig.Algorithm, sig.Status)
		}
	}
}

func TestProvenanceVerifyRustSignedPng(t *testing.T) {
	skipIfFixturesMissing(t)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	target := filepath.Join(provenanceFixturesDir(t), "rust_signed_ed25519.png")
	result, err := agent.VerifyImage(target, &VerifyImageOpts{KeyDir: provenanceKeysDir(t)})
	if err != nil {
		t.Fatalf("VerifyImage: %v", err)
	}
	if result.Status != "valid" {
		t.Fatalf("status=%q, want valid", result.Status)
	}
	if result.Format != "png" {
		t.Fatalf("format=%q, want png", result.Format)
	}
}

func TestProvenanceVerifyRustSignedJpeg(t *testing.T) {
	skipIfFixturesMissing(t)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	target := filepath.Join(provenanceFixturesDir(t), "rust_signed_ed25519.jpg")
	result, err := agent.VerifyImage(target, &VerifyImageOpts{KeyDir: provenanceKeysDir(t)})
	if err != nil {
		t.Fatalf("VerifyImage: %v", err)
	}
	if result.Status != "valid" {
		t.Fatalf("status=%q, want valid", result.Status)
	}
	if result.Format != "jpeg" {
		t.Fatalf("format=%q, want jpeg", result.Format)
	}
}

func TestProvenanceVerifyRustSignedWebp(t *testing.T) {
	skipIfFixturesMissing(t)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	target := filepath.Join(provenanceFixturesDir(t), "rust_signed_ed25519.webp")
	result, err := agent.VerifyImage(target, &VerifyImageOpts{KeyDir: provenanceKeysDir(t)})
	if err != nil {
		t.Fatalf("VerifyImage: %v", err)
	}
	if result.Status != "valid" {
		t.Fatalf("status=%q, want valid", result.Status)
	}
	if result.Format != "webp" {
		t.Fatalf("format=%q, want webp", result.Format)
	}
}

// ---------------------------------------------------------------------------
// C3 — yaml.v3 parses the Rust-signed markdown signature block body.
// ---------------------------------------------------------------------------

func TestProvenanceYamlParsesRustSignedBlockBody(t *testing.T) {
	skipIfFixturesMissing(t)

	content, err := os.ReadFile(filepath.Join(provenanceFixturesDir(t), "rust_signed_ed25519.md"))
	if err != nil {
		t.Fatal(err)
	}
	beginMarker := "-----BEGIN JACS SIGNATURE-----\n"
	endMarker := "\n-----END JACS SIGNATURE-----"
	beginIdx := strings.Index(string(content), beginMarker)
	if beginIdx < 0 {
		t.Fatal("no BEGIN marker found")
	}
	endIdx := strings.Index(string(content), endMarker)
	if endIdx < 0 {
		t.Fatal("no END marker found")
	}
	body := string(content[beginIdx+len(beginMarker) : endIdx])

	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	for _, key := range []string{"signer", "signedContentHash", "publicKeyHash", "algorithm", "signature"} {
		if _, ok := parsed[key]; !ok {
			t.Fatalf("missing %q in parsed YAML body: %#v", key, parsed)
		}
	}
}

// ---------------------------------------------------------------------------
// C1 — strict + permissive parity for unsigned fixtures.
// ---------------------------------------------------------------------------

func TestProvenancePermissiveUnsignedMarkdown(t *testing.T) {
	skipIfFixturesMissing(t)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	target := filepath.Join(provenanceFixturesDir(t), "unsigned.md")
	result, err := agent.VerifyText(target, nil)
	if err != nil {
		t.Fatalf("permissive verify: %v", err)
	}
	if result.Status != "missing_signature" {
		t.Fatalf("status=%q, want missing_signature", result.Status)
	}
}

func TestProvenanceStrictUnsignedMarkdown(t *testing.T) {
	skipIfFixturesMissing(t)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	target := filepath.Join(provenanceFixturesDir(t), "unsigned.md")
	_, err = agent.VerifyText(target, &VerifyTextOpts{Strict: true})
	if err == nil {
		t.Fatal("expected strict verify to error")
	}
	if !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected ErrMissingSignature, got %v", err)
	}
}

func TestProvenancePermissiveUnsignedImages(t *testing.T) {
	skipIfFixturesMissing(t)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	for _, fixture := range []struct {
		name string
		fmt  string
	}{
		{"unsigned.png", "png"},
		{"unsigned.jpg", "jpeg"},
		{"unsigned.webp", "webp"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			target := filepath.Join(provenanceFixturesDir(t), fixture.name)
			result, err := agent.VerifyImage(target, nil)
			if err != nil {
				t.Fatalf("permissive verify: %v", err)
			}
			if result.Status != "missing_signature" {
				t.Fatalf("status=%q, want missing_signature", result.Status)
			}
			if result.Format != fixture.fmt {
				t.Fatalf("format=%q, want %q", result.Format, fixture.fmt)
			}
		})
	}
}

func TestProvenanceStrictUnsignedImages(t *testing.T) {
	skipIfFixturesMissing(t)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	for _, fixture := range []string{"unsigned.png", "unsigned.jpg", "unsigned.webp"} {
		t.Run(fixture, func(t *testing.T) {
			target := filepath.Join(provenanceFixturesDir(t), fixture)
			_, err := agent.VerifyImage(target, &VerifyImageOpts{Strict: true})
			if err == nil {
				t.Fatal("expected strict verify to error")
			}
			if !errors.Is(err, ErrMissingSignature) {
				t.Fatalf("expected ErrMissingSignature, got %v", err)
			}
		})
	}
}

func TestProvenanceStrictRustSignedMarkdownDoesNotError(t *testing.T) {
	skipIfFixturesMissing(t)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	target := filepath.Join(provenanceFixturesDir(t), "rust_signed_ed25519.md")
	result, err := agent.VerifyText(target, &VerifyTextOpts{
		Strict: true,
		KeyDir: provenanceKeysDir(t),
	})
	if err != nil {
		t.Fatalf("strict verify on signed file errored: %v", err)
	}
	if result.Status != "signed" {
		t.Fatalf("status=%q, want signed", result.Status)
	}
}

// ---------------------------------------------------------------------------
// Acceptance #2 — Go signs locally, Rust CLI verifies (round trip).
// ---------------------------------------------------------------------------

func TestProvenanceGoSignsRustVerifies(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not on PATH; skipping Go→Rust round-trip")
	}

	tmp := t.TempDir()
	target := filepath.Join(tmp, "go_signed.md")
	if err := os.WriteFile(target, []byte("# Go-signed\n\nVerify me from Rust.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	if err := agent.SignText(target, &SignTextOpts{NoBackup: true}); err != nil {
		t.Fatalf("SignText: %v", err)
	}

	signerID, err := agent.GetAgentID()
	if err != nil {
		t.Fatalf("GetAgentID: %v", err)
	}
	pem, err := agent.GetPublicKeyPEM()
	if err != nil {
		t.Fatalf("GetPublicKeyPEM: %v", err)
	}

	keyDir := filepath.Join(tmp, "keys")
	if err := os.Mkdir(keyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	encoded := strings.ReplaceAll(strings.ReplaceAll(signerID, "..", "%2E%2E"), ":", "%3A")
	keyPath := filepath.Join(keyDir, encoded+".public.pem")
	if err := os.WriteFile(keyPath, []byte(pem), 0o644); err != nil {
		t.Fatal(err)
	}

	workspaceRoot := filepath.Clean(filepath.Join(provenanceFixturesDir(t), "..", "..", "..", ".."))

	cmd := exec.Command(
		"cargo", "run", "-q", "--bin", "jacs", "--",
		"verify-text", target,
		"--key-dir", keyDir,
		"--json",
	)
	cmd.Dir = workspaceRoot
	cmd.Env = append(os.Environ(), "JACS_MAX_IAT_SKEW_SECONDS=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cargo verify-text failed: %v\noutput: %s", err, out)
	}

	// Filter out warning lines that cargo may emit before the JSON payload.
	jsonStart := strings.Index(string(out), "{")
	if jsonStart < 0 {
		t.Fatalf("no JSON payload in cargo output: %s", out)
	}
	var parsed struct {
		Status     string `json:"status"`
		Signatures []struct {
			Status   string `json:"status"`
			SignerID string `json:"signer_id"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(out[jsonStart:], &parsed); err != nil {
		t.Fatalf("unmarshal cli output: %v\noutput: %s", err, out)
	}
	if parsed.Status != "signed" {
		t.Fatalf("status=%q, want signed", parsed.Status)
	}
	if len(parsed.Signatures) != 1 {
		t.Fatalf("got %d signatures, want 1", len(parsed.Signatures))
	}
	sig := parsed.Signatures[0]
	if sig.Status != "valid" {
		t.Fatalf("sig status=%q, want valid", sig.Status)
	}
	if sig.SignerID != signerID {
		t.Fatalf("sig signer_id=%q, want %q", sig.SignerID, signerID)
	}
}
