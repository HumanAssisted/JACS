package jacs

// NOTE: This test deliberately does NOT `import "C"`. cgo is not supported in
// in-package (_test.go, package jacs) test files (golang/go#4030); doing so
// fails `go vet`/`go build`/`go test -c` with "use of cgo in test not
// supported". We read C strings back through the cGoString helper in cstr.go.

import "testing"

func TestCStringRoundTrip(t *testing.T) {
	c, free := cString("hello")
	defer free()
	if got := cGoString(c); got != "hello" {
		t.Fatalf("cString round-trip = %q, want %q", got, "hello")
	}
}

func TestCStringOptNil(t *testing.T) {
	c, free := cStringOpt(nil)
	if c != nil {
		t.Fatalf("cStringOpt(nil) returned non-nil C string")
	}
	// The returned free func must be safe to call (no panic) for the nil case.
	free()
}

func TestCStringOptSome(t *testing.T) {
	s := "world"
	c, free := cStringOpt(&s)
	defer free()
	if c == nil {
		t.Fatalf("cStringOpt(&s) returned nil C string")
	}
	if got := cGoString(c); got != "world" {
		t.Fatalf("cStringOpt(&s) = %q, want %q", got, "world")
	}
}
