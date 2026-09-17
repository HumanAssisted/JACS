package jacs

// noCopy is recognized by go vet's copylocks analyzer. It belongs on the
// private heap state, where copying would duplicate synchronization state.
// The public wrappers intentionally remain safe to copy because they contain
// only a pointer to that shared state.
//
// See https://pkg.go.dev/sync#Mutex for the lock-copying constraint this
// sentinel documents.
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}
