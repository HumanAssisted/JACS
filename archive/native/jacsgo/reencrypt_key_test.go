package jacs

// Tests for the hardened private-key re-encryption FFI path (finding M3).
//
// `JacsAgent.ReencryptKey` must route through the SAME hardened key-write
// primitive that the other language bindings use
// (`jacs_binding_core::AgentWrapper::reencrypt_key` ->
// `jacs::crypt::aes_encrypt::reencrypt_private_key_file`). That primitive:
//   - refuses to follow symlinks on read and write,
//   - rejects path-traversal in the config-derived key filename,
//   - replaces the key file atomically,
//   - writes the re-encrypted key material with owner-only 0o600 permissions.
//
// The previous Go FFI export read+overwrote the key file directly with
// `std::fs::write`, which inherited the process umask (typically world/group
// readable, 0o644) and followed symlinks. The assertions below would fail
// against that old direct-overwrite path and pass once the export delegates to
// the hardened primitive.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// reencryptTestEnv creates a persistent on-disk agent (config + encrypted
// private key) inside a temp CWD, loads it into a JacsAgent handle, and returns
// the handle plus the absolute path to the encrypted private key file.
func reencryptTestEnv(t *testing.T) (*JacsAgent, string) {
	t.Helper()
	skipIfLibraryMissing(t)

	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits not meaningful on Windows")
	}

	tmpDir := canonicalTempDir(t)
	originalCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	originalPassword, hadPassword := os.LookupEnv("JACS_PRIVATE_KEY_PASSWORD")

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to temp dir: %v", err)
	}
	t.Cleanup(func() {
		if hadPassword {
			_ = os.Setenv("JACS_PRIVATE_KEY_PASSWORD", originalPassword)
		} else {
			_ = os.Unsetenv("JACS_PRIVATE_KEY_PASSWORD")
		}
		_ = os.Chdir(originalCwd)
	})

	const oldPassword = "OldP@ss123!#"
	if err := os.Setenv("JACS_PRIVATE_KEY_PASSWORD", oldPassword); err != nil {
		t.Fatalf("failed to set password env var: %v", err)
	}

	algorithm := "ring-Ed25519"
	dataDir := "jacs_data"
	keyDir := "jacs_keys"
	configPath := "jacs.config.json"
	if _, err := CreateAgent(
		"go-reencrypt-agent", oldPassword,
		&algorithm, &dataDir, &keyDir, &configPath,
		nil, nil, nil, nil,
	); err != nil {
		t.Fatalf("CreateAgent failed: %v", err)
	}

	agent, err := NewJacsAgent()
	if err != nil {
		t.Fatalf("NewJacsAgent failed: %v", err)
	}
	t.Cleanup(func() { agent.Close() })

	if err := agent.Load(configPath); err != nil {
		t.Fatalf("Load(%q) failed: %v", configPath, err)
	}

	keyPath := filepath.Join(tmpDir, keyDir, "jacs.private.pem.enc")
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected encrypted key at %s: %v", keyPath, err)
	}
	return agent, keyPath
}

// TestReencryptKeyWritesOwnerOnlyPerms asserts that after a successful
// re-encryption the rewritten private key file has owner-only 0o600
// permissions. This fails against the old direct `std::fs::write` overwrite
// (which left umask-derived perms, e.g. 0o644) and passes once the export
// delegates to the hardened `reencrypt_private_key_file` primitive.
func TestReencryptKeyWritesOwnerOnlyPerms(t *testing.T) {
	agent, keyPath := reencryptTestEnv(t)

	// Deliberately loosen perms first so the assertion proves the rewrite
	// re-tightens to 0o600 (rather than merely preserving an already-tight bit).
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("failed to pre-set loose perms: %v", err)
	}

	const newPassword = "NewP@ss456!#"
	if err := agent.ReencryptKey("OldP@ss123!#", newPassword); err != nil {
		t.Fatalf("ReencryptKey failed: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat re-encrypted key: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Fatalf("re-encrypted key perms = %o, want 0600 (hardened path lost; "+
			"export is using a non-secure write)", perm)
	}
}

// TestReencryptKeyRejectsSymlinkedKeyFile asserts that if the private key path
// is a symlink, re-encryption refuses to follow it (the hardened primitive does
// not follow symlinks). The old direct-overwrite path followed symlinks and
// would have rewritten the link target instead.
func TestReencryptKeyRejectsSymlinkedKeyFile(t *testing.T) {
	agent, keyPath := reencryptTestEnv(t)

	// Move the real key aside and replace the configured key path with a
	// symlink pointing at it.
	realKey := keyPath + ".real"
	if err := os.Rename(keyPath, realKey); err != nil {
		t.Fatalf("failed to move real key aside: %v", err)
	}
	if err := os.Symlink(realKey, keyPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// Capture the symlink target's content so we can prove it was not rewritten.
	before, err := os.ReadFile(realKey)
	if err != nil {
		t.Fatalf("read real key: %v", err)
	}

	err = agent.ReencryptKey("OldP@ss123!#", "NewP@ss456!#")
	if err == nil {
		t.Fatal("ReencryptKey through a symlinked key path should fail (hardened " +
			"path refuses to follow symlinks)")
	}

	after, readErr := os.ReadFile(realKey)
	if readErr != nil {
		t.Fatalf("read real key after: %v", readErr)
	}
	if string(before) != string(after) {
		t.Fatal("symlink target was rewritten; export followed the symlink " +
			"instead of rejecting it")
	}
}
