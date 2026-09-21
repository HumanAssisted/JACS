package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func fixtureClient(fixtures map[string][]byte) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		payload, ok := fixtures[filepath.Base(req.URL.Path)]
		status := http.StatusOK
		if !ok {
			status = http.StatusNotFound
			payload = []byte("not found")
		}
		return &http.Response{
			StatusCode: status,
			Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(payload)),
			Request:    req,
		}, nil
	})}
}

func TestReleaseAssetForSupportedPlatforms(t *testing.T) {
	tests := []struct {
		goos, goarch, wantAsset, wantLibrary string
	}{
		{"darwin", "arm64", "jacsgo-v0.11.4-darwin-arm64.dylib", "libjacsgo.dylib"},
		{"darwin", "amd64", "jacsgo-v0.11.4-darwin-amd64.dylib", "libjacsgo.dylib"},
		{"linux", "arm64", "jacsgo-v0.11.4-linux-arm64.so", "libjacsgo.so"},
		{"linux", "amd64", "jacsgo-v0.11.4-linux-amd64.so", "libjacsgo.so"},
	}

	for _, test := range tests {
		t.Run(test.goos+"-"+test.goarch, func(t *testing.T) {
			asset, library, err := releaseAsset("v0.11.4", test.goos, test.goarch)
			if err != nil {
				t.Fatalf("releaseAsset: %v", err)
			}
			if asset != test.wantAsset || library != test.wantLibrary {
				t.Fatalf("got (%q, %q), want (%q, %q)", asset, library, test.wantAsset, test.wantLibrary)
			}
		})
	}

	if _, _, err := releaseAsset("v0.11.4", "windows", "amd64"); err == nil {
		t.Fatal("unsupported Windows platform must be rejected")
	}
}

func TestChecksumForRejectsMissingDuplicateAndMalformedEntries(t *testing.T) {
	const asset = "jacsgo-v0.11.4-linux-amd64.so"
	const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	got, err := checksumFor([]byte(digest+"  "+asset+"\n"), asset)
	if err != nil || got != digest {
		t.Fatalf("checksumFor valid entry = (%q, %v), want (%q, nil)", got, err, digest)
	}
	if _, err := checksumFor([]byte(digest+"  other.so\n"), asset); err == nil {
		t.Fatal("missing asset checksum must fail")
	}
	if _, err := checksumFor([]byte(digest+"  "+asset+"\n"+digest+" *"+asset+"\n"), asset); err == nil {
		t.Fatal("duplicate asset checksum must fail")
	}
	if _, err := checksumFor([]byte("not-a-sha256  "+asset+"\n"), asset); err == nil {
		t.Fatal("malformed checksum must fail")
	}
}

func TestReleaseDownloadURLUsesEncodedSemanticTagAndHTTPS(t *testing.T) {
	got, err := releaseDownloadURL(
		"https://github.com/HumanAssisted/JACS/releases/download",
		"jacsgo/v0.11.4",
		"jacsgo-v0.11.4-darwin-arm64.dylib",
	)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://github.com/HumanAssisted/JACS/releases/download/jacsgo%2Fv0.11.4/jacsgo-v0.11.4-darwin-arm64.dylib"
	if got != want {
		t.Fatalf("release URL %q, want %q", got, want)
	}
	if _, err := releaseDownloadURL("http://github.com/releases/download", "jacsgo/v0.11.4", "asset"); err == nil {
		t.Fatal("non-HTTPS release base must fail")
	}
}

func TestInstallNativeVerifiesChecksumAndWritesExpectedLibrary(t *testing.T) {
	const version = "v0.11.4"
	const asset = "jacsgo-v0.11.4-linux-amd64.so"
	payload := []byte("test-native-library")
	digest := fmt.Sprintf("%x", sha256.Sum256(payload))

	client := fixtureClient(map[string][]byte{
		asset:                           payload,
		"jacsgo-v0.11.4-sha256sums.txt": []byte(fmt.Sprintf("%s  %s\n", digest, asset)),
	})

	moduleDir := filepath.Join(t.TempDir(), "jacsgo")
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	err := installNative(context.Background(), installOptions{
		Version:     version,
		GOOS:        "linux",
		GOARCH:      "amd64",
		ModuleDir:   moduleDir,
		ReleaseBase: "https://releases.example.test",
		Client:      client,
	})
	if err != nil {
		t.Fatalf("installNative: %v", err)
	}

	installed, err := os.ReadFile(filepath.Join(moduleDir, "build", "libjacsgo.so"))
	if err != nil {
		t.Fatal(err)
	}
	if string(installed) != string(payload) {
		t.Fatalf("installed bytes %q, want %q", installed, payload)
	}
}

func TestInstallNativeRejectsChecksumMismatchWithoutReplacingLibrary(t *testing.T) {
	const asset = "jacsgo-v0.11.4-linux-amd64.so"
	client := fixtureClient(map[string][]byte{
		asset:                           []byte("tampered"),
		"jacsgo-v0.11.4-sha256sums.txt": []byte(fmt.Sprintf("%064x  %s\n", 1, asset)),
	})

	moduleDir := filepath.Join(t.TempDir(), "jacsgo")
	buildDir := filepath.Join(moduleDir, "build")
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		t.Fatal(err)
	}
	libraryPath := filepath.Join(buildDir, "libjacsgo.so")
	if err := os.WriteFile(libraryPath, []byte("known-good"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := installNative(context.Background(), installOptions{
		Version:     "v0.11.4",
		GOOS:        "linux",
		GOARCH:      "amd64",
		ModuleDir:   moduleDir,
		ReleaseBase: "https://releases.example.test",
		Client:      client,
	})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("got %v, want checksum mismatch", err)
	}
	installed, readErr := os.ReadFile(libraryPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(installed) != "known-good" {
		t.Fatalf("existing library was replaced with %q", installed)
	}
}

func TestDefaultVendorModuleDirRequiresMatchingSemanticVersion(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/consumer\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	vendorDir := filepath.Join(root, "vendor")
	moduleDir := filepath.Join(vendorDir, "github.com", "HumanAssisted", "JACS", "jacsgo")
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	modules := "# github.com/HumanAssisted/JACS/jacsgo v0.11.4\n## explicit; go 1.21\ngithub.com/HumanAssisted/JACS/jacsgo\n"
	if err := os.WriteFile(filepath.Join(vendorDir, "modules.txt"), []byte(modules), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := defaultVendorModuleDir(root, "v0.11.4")
	if err != nil || got != moduleDir {
		t.Fatalf("defaultVendorModuleDir = (%q, %v), want (%q, nil)", got, err, moduleDir)
	}
	if _, err := defaultVendorModuleDir(root, "v0.11.3"); err == nil {
		t.Fatal("installer version that differs from vendored module must fail")
	}
}
