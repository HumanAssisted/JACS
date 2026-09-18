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

The examples run with or without JACS config; if no config is found, requests are sent unsigned and the server responds without signing. Set `JACS_CONFIG` to a config path and ensure `jacs.server.config.json` / `jacs.client.config.json` exist in the working directory if you want signing.

The examples demonstrate JACS request signing and response verification over HTTP.
