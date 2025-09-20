# JACS HTTP Examples

This directory contains HTTP client and server examples demonstrating JACS integration.

## Building

Both client and server use build tags to avoid main function conflicts:

```bash
# Build server
go build -tags server -o server

# Build client
go build -tags client -o client

# Or build both using the Makefile
cd ../.. && make examples
```

## Running

1. Start the server:
```bash
./server
```

2. In another terminal, run the client:
```bash
./client
```

The examples demonstrate JACS request signing and response verification over HTTP.
