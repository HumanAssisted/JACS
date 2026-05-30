package jacs

/*
#include <stdlib.h>
*/
import "C"
import "unsafe"

// cString copies s into a C string and returns it together with a free func.
// Always call the returned func (defer it) after the C call returns.
func cString(s string) (*C.char, func()) {
	c := C.CString(s)
	return c, func() { C.free(unsafe.Pointer(c)) }
}

// cStringOpt is the optional-pointer variant: nil -> (nil, no-op free).
func cStringOpt(s *string) (*C.char, func()) {
	if s == nil {
		return nil, func() {}
	}
	return cString(*s)
}

// cGoString copies a C string back into a Go string.
//
// It exists so that tests (which live in the same package and therefore cannot
// `import "C"` themselves — cgo is unsupported in in-package _test.go files,
// see golang/go#4030) can read back values produced by cString/cStringOpt.
func cGoString(c *C.char) string {
	return C.GoString(c)
}
