The standard `JacsAgent` I/O methods and simple signing helpers are async.
Selected operations also provide `Sync` variants. Standalone verification,
trust helpers and several low-level `JacsSimpleAgent` methods are synchronous;
check the API signature for the method you call.
