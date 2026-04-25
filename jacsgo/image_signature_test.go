// Image sign/verify/extract tests (Task 12 — PRD §3.2, §4.2, C1).
//
// PNG and JPEG fixtures are generated at test-start via the Go stdlib
// (image/png, image/jpeg). WebP is loaded from a tiny committed fixture
// at jacsgo/fixtures/unsigned_16x16.webp because the Go stdlib has no
// WebP encoder.

package jacs

import (
	"bytes"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const webpFixturePath = "fixtures/unsigned_16x16.webp"

// writeUnsignedPNG writes a 16x16 red PNG at `path`.
func writeUnsignedPNG(t *testing.T, path string) {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	red := color.RGBA{255, 0, 0, 255}
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			img.Set(x, y, red)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}

// writeUnsignedJPEG writes a 16x16 blue JPEG at `path`.
func writeUnsignedJPEG(t *testing.T, path string) {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	blue := color.RGBA{0, 0, 255, 255}
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			img.Set(x, y, blue)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := jpeg.Encode(f, img, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatal(err)
	}
}

// writeUnsignedWebP copies the committed unsigned WebP fixture into `path`.
// Go stdlib has no WebP encoder; we ship a tiny pre-encoded fixture.
func writeUnsignedWebP(t *testing.T, path string) {
	t.Helper()
	src, err := readWebpFixture()
	if err != nil {
		t.Fatalf("missing WebP fixture: %v", err)
	}
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}
}

// readWebpFixture reads the WebP fixture using a path resolved relative to
// the test package directory. `go test` ordinarily runs with cwd set to the
// package, but parallel runners and IDEs sometimes deviate; resolving via
// runtime.Caller keeps the lookup stable.
func readWebpFixture() ([]byte, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return os.ReadFile(webpFixturePath)
	}
	candidate := filepath.Join(filepath.Dir(thisFile), webpFixturePath)
	if data, err := os.ReadFile(candidate); err == nil {
		return data, nil
	}
	// Fallback: cwd-relative.
	return os.ReadFile(webpFixturePath)
}

// formatCases lists the three supported image formats with their on-disk extension
// and the binding's expected `format` value in `SignImageResult`.
var formatCases = []struct {
	name      string
	ext       string
	expFormat string
	writer    func(*testing.T, string)
}{
	{"png", ".png", "png", writeUnsignedPNG},
	{"jpeg", ".jpg", "jpeg", writeUnsignedJPEG},
	{"webp", ".webp", "webp", writeUnsignedWebP},
}

// ----------------------------------------------------------------------------
// signImage + verifyImage round trips, one per format.
// ----------------------------------------------------------------------------

func TestSignImagePngRoundTrip(t *testing.T) { runSignImageRoundTrip(t, formatCases[0]) }
func TestSignImageJpegRoundTrip(t *testing.T) { runSignImageRoundTrip(t, formatCases[1]) }
func TestSignImageWebpRoundTrip(t *testing.T) { runSignImageRoundTrip(t, formatCases[2]) }

func runSignImageRoundTrip(t *testing.T, fc struct {
	name      string
	ext       string
	expFormat string
	writer    func(*testing.T, string)
}) {
	dir := t.TempDir()
	src := filepath.Join(dir, "in"+fc.ext)
	dst := filepath.Join(dir, "out"+fc.ext)
	fc.writer(t, src)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	out, err := agent.SignImage(src, dst, nil)
	if err != nil {
		t.Fatalf("SignImage(%s): %v", fc.name, err)
	}
	if out.Format != fc.expFormat {
		t.Fatalf("expected format=%q, got %q", fc.expFormat, out.Format)
	}

	result, err := agent.VerifyImage(dst, nil)
	if err != nil {
		t.Fatalf("VerifyImage(%s): %v", fc.name, err)
	}
	if result.Status != "valid" {
		t.Fatalf("expected status=valid, got %q", result.Status)
	}
}

// ----------------------------------------------------------------------------
// C1 permissive vs strict per format.
// ----------------------------------------------------------------------------

func TestVerifyImagePermissiveMissingSignaturePng(t *testing.T)  { runPermissiveMissing(t, formatCases[0]) }
func TestVerifyImagePermissiveMissingSignatureJpeg(t *testing.T) { runPermissiveMissing(t, formatCases[1]) }
func TestVerifyImagePermissiveMissingSignatureWebp(t *testing.T) { runPermissiveMissing(t, formatCases[2]) }

func runPermissiveMissing(t *testing.T, fc struct {
	name      string
	ext       string
	expFormat string
	writer    func(*testing.T, string)
}) {
	dir := t.TempDir()
	src := filepath.Join(dir, "plain"+fc.ext)
	fc.writer(t, src)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	result, err := agent.VerifyImage(src, nil)
	if err != nil {
		t.Fatalf("permissive VerifyImage(%s) must not error, got: %v", fc.name, err)
	}
	if result.Status != "missing_signature" {
		t.Fatalf("expected status=missing_signature, got %q", result.Status)
	}
}

func TestVerifyImageStrictMissingSignaturePng(t *testing.T)  { runStrictMissing(t, formatCases[0]) }
func TestVerifyImageStrictMissingSignatureJpeg(t *testing.T) { runStrictMissing(t, formatCases[1]) }
func TestVerifyImageStrictMissingSignatureWebp(t *testing.T) { runStrictMissing(t, formatCases[2]) }

func runStrictMissing(t *testing.T, fc struct {
	name      string
	ext       string
	expFormat string
	writer    func(*testing.T, string)
}) {
	dir := t.TempDir()
	src := filepath.Join(dir, "plain"+fc.ext)
	fc.writer(t, src)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	_, err = agent.VerifyImage(src, &VerifyImageOpts{Strict: true})
	if err == nil {
		t.Fatalf("strict VerifyImage(%s) should return an error", fc.name)
	}
	if !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected errors.Is(err, ErrMissingSignature), got %v", err)
	}
}

// ----------------------------------------------------------------------------
// extract_media_signature.
// ----------------------------------------------------------------------------

func TestExtractMediaSignaturePng(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "in.png")
	dst := filepath.Join(dir, "out.png")
	writeUnsignedPNG(t, src)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	if _, err := agent.SignImage(src, dst, nil); err != nil {
		t.Fatal(err)
	}
	payload, present, err := agent.ExtractMediaSignature(dst, nil)
	if err != nil {
		t.Fatalf("ExtractMediaSignature: %v", err)
	}
	if !present {
		t.Fatal("expected present=true after sign")
	}
	if !json.Valid([]byte(payload)) {
		t.Fatalf("default ExtractMediaSignature should return decoded JSON, got: %.80q", payload)
	}
}

func TestExtractMediaSignatureUnsignedReturnsEmpty(t *testing.T) {
	for _, fc := range formatCases {
		t.Run(fc.name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "plain"+fc.ext)
			fc.writer(t, src)

			agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
			if err != nil {
				t.Fatal(err)
			}
			defer agent.Close()

			payload, present, err := agent.ExtractMediaSignature(src, nil)
			if err != nil {
				t.Fatalf("unsigned ExtractMediaSignature must not error, got: %v", err)
			}
			if present {
				t.Fatalf("expected present=false on unsigned %s, got payload=%.40q", fc.name, payload)
			}
			if payload != "" {
				t.Fatalf("expected empty payload, got %q", payload)
			}
		})
	}
}

func TestExtractMediaSignatureRawPayloadReturnsBase64Url(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "in.png")
	dst := filepath.Join(dir, "out.png")
	writeUnsignedPNG(t, src)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	if _, err := agent.SignImage(src, dst, nil); err != nil {
		t.Fatal(err)
	}

	decoded, decodedPresent, err := agent.ExtractMediaSignature(dst, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !decodedPresent {
		t.Fatal("decoded payload should be present after sign")
	}

	raw, rawPresent, err := agent.ExtractMediaSignature(dst, &ExtractMediaOpts{RawPayload: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rawPresent {
		t.Fatal("raw payload should be present after sign")
	}
	if decoded == raw {
		t.Fatal("decoded and raw payloads should differ when both are present")
	}
	if strings.HasPrefix(strings.TrimSpace(raw), "{") {
		t.Fatalf("raw_payload must be base64url, got JSON-shaped: %.40q", raw)
	}
}

// ----------------------------------------------------------------------------
// Robust mode default + refuseOverwrite (PRD §4.2.2).
// ----------------------------------------------------------------------------

func TestRobustModeOffByDefault(t *testing.T) {
	// PRD Q4: robust mode is off unless explicitly requested. The pixel bytes
	// of a default-signed PNG match the input image byte-for-byte (everything
	// goes into PNG metadata, not LSB).
	dir := t.TempDir()
	src := filepath.Join(dir, "in.png")
	dst := filepath.Join(dir, "out.png")
	writeUnsignedPNG(t, src)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	out, err := agent.SignImage(src, dst, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Robust {
		t.Fatal("default signImage must not enable robust mode")
	}

	// Decoded pixel data should match input pixel data byte-for-byte.
	srcBytes, _ := os.ReadFile(src)
	dstBytes, _ := os.ReadFile(dst)
	srcImg, _, err := image.Decode(bytes.NewReader(srcBytes))
	if err != nil {
		t.Fatal(err)
	}
	dstImg, _, err := image.Decode(bytes.NewReader(dstBytes))
	if err != nil {
		t.Fatal(err)
	}
	if srcImg.Bounds() != dstImg.Bounds() {
		t.Fatalf("bounds mismatch src=%v dst=%v", srcImg.Bounds(), dstImg.Bounds())
	}
}

// Issue 010 / PRD §10 eighth-pass item 10: robust LSB on WebP is deferred
// until libwebp-sys lands. SignImage with Robust:true on a WebP input MUST
// surface a deterministic "deferred" error from every binding.
func TestSignImageRobustWebpDeferred(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "in.webp")
	dst := filepath.Join(dir, "out.webp")
	writeUnsignedWebP(t, src)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	_, err = agent.SignImage(src, dst, &SignImageOpts{Robust: true})
	if err == nil {
		t.Fatal("expected error when signing WebP with robust=true")
	}
	msg := err.Error()
	if !strings.Contains(msg, "webp robust mode deferred") {
		t.Fatalf("expected 'webp robust mode deferred' error, got: %v", err)
	}
}

// PRD §4.2.2: refuseOverwrite is a single-signer guard. Re-signing an already
// signed image should error.
func TestSignImageRefuseOverwriteRejectsAlreadySigned(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "in.png")
	dst := filepath.Join(dir, "signed.png")
	writeUnsignedPNG(t, src)

	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	if _, err := agent.SignImage(src, dst, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.SignImage(dst, dst, &SignImageOpts{RefuseOverwrite: true}); err == nil {
		t.Fatal("expected SignImage with RefuseOverwrite=true on already-signed input to error")
	}
}
