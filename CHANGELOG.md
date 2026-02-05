## 0.5.2

### Security

- **[CRITICAL] Fixed trust store path traversal**: Agent IDs used in trust store file operations are now validated as proper UUID:UUID format and resulting paths are canonicalized to prevent directory traversal attacks via malicious agent IDs.

- **[CRITICAL] Fixed URL injection in HAI key fetch**: `agent_id` and `version` parameters in `fetch_public_key_from_hai()` and `verify_hai_registration_sync()` are now validated as UUIDs before URL interpolation, preventing path traversal in HTTP requests.

- **[HIGH] Added configurable signature expiration**: Signatures can now be configured to expire via `JACS_MAX_SIGNATURE_AGE_SECONDS` env var (e.g., `7776000` for 90 days). Default is `0` (no expiration) since JACS documents are designed to be idempotent and eternal.

- **[HIGH] Added strict algorithm enforcement mode**: Set `JACS_REQUIRE_EXPLICIT_ALGORITHM=true` to reject signature verification when `signingAlgorithm` is missing, preventing heuristic-based algorithm detection.

- **[HIGH] Fixed memory leak in schema domain whitelist**: Replaced `Box::leak()` with `OnceLock` for one-time parsing of `JACS_SCHEMA_ALLOWED_DOMAINS`, preventing unbounded memory growth.

- **[MEDIUM] Improved signed content canonicalization**: Fields are now sorted alphabetically before signing, non-string fields use canonical JSON serialization, and verification fails if zero fields are extracted.

- **[MEDIUM] Added HTTPS enforcement for HAI key service**: `HAI_KEYS_BASE_URL` must use HTTPS (localhost exempted for testing).

- **[MEDIUM] Added plaintext key warning**: Loading unencrypted private keys now emits a `tracing::warn` recommending encryption.

- **[LOW] Increased PBKDF2 iterations to 600,000**: Per OWASP 2024 recommendation (was 100,000). Automatic migration fallback: decryption tries new count first, then falls back to legacy 100,000 with a warning to re-encrypt.

- **[LOW] Deprecated `decrypt_private_key()`**: Use `decrypt_private_key_secure()` which returns `ZeroizingVec` for automatic memory zeroization.

- **[LOW] Added rate limiting on HAI key fetch**: Outgoing requests to the HAI key service are now rate-limited (2 req/s, burst of 3) using the existing `RateLimiter`.

- **[LOW] Renamed `JACS_USE_SECURITY` to `JACS_ENABLE_FILESYSTEM_QUARANTINE`**: Clarifies that this setting only controls filesystem quarantine of executable files, not cryptographic verification. Old name still works with a deprecation warning.

### Migration Notes

- Keys encrypted with pre-0.5.2 PBKDF2 iterations (100k) are automatically decrypted via fallback, but new encryptions use 600k iterations. Re-encrypt existing keys for improved security.

# PLANNED
-  machine fingerprinting v2
- passkey-client integration
- encrypt files at rest
- refine schema usage
- more getters and setters for documents recognized by schemas
- WASM builds
 - https://github.com/verus-lang/verus?tab=readme-ov-file
- use rcgen to sign certs, and register with ACME
 https://opentelemetry.io/docs/languages/rust/
. ai.pydantic.dev
- secure storage of private key for shared server envs https://crates.io/crates/tss-esapi, https://docs.rs/cryptoki/latest/cryptoki/
- qr code integration
- https://github.com/sourcemeta/one

## 0.4.0
- Domain integration
- [] sign config
 - [] RBAC enforcement from server. If shared, new version is pinned. 

  - more complete python implementation
   - pass document string or document id - with optional version instead of string
   - load document whatever storage config is
   - function test output metadata about current config and current agent

- [] add more feature flags for modular integrations
- [] a2a integration
- [] acp integration


## jacs-mcp 0.1.0

 - [] use rmcp
 - [] auth or all features
 - [] integration test with client
 - [] https://github.com/modelcontextprotocol/specification/discussions

### devrel
- [] github actions builder for auto build/deploy of platform specific versions
--------------------

- [] cli install for brew
- [] cli install via shell script
- [] open license
 - [] api for easier integratios data processing 

 - [] clickhous demo
 - [] test centralized logging output without file output 
 
--------------------

## 0.3.7

### internals

- [x] Updated A2A integration to protocol v0.4.0: rewrote AgentCard schema (protocolVersions array, supportedInterfaces, embedded JWS signatures, SecurityScheme enum, AgentSkill with id/tags), updated well-known path to agent-card.json, and aligned Rust, Python, and Node.js bindings with passing tests across all three.
- [] remove in memory map if users don't request it. Refactor and DRY storage to prep for DB storage
- [] test a2a across libraries
- [] store in database
- [] awareness of branch, merge, latest for documents. 

### hai.ai

- integration with 

 1. register
 2. 


### jacsnpm

 - [] BUG with STDIO in general
      fix issues with Stdio mcp client and server log noise - relates to open telemetry being used at rust layer.

 - [] npm install jacs (cli and available to plugin)
 - [] a2a integration
 - [] integrate cli

### jacspy
 - [] mcp make sure "list" request is signed?
 - [] some integration tests
 - [] fastapi, django, flask, guvicorn specific pre-built middleware
 - [] auto generate agent doc from MCP server list, auto versions (important for A2A as well)
 - [] fastmcp client and server websocket
 - [] BUG? demo fastmcp client and server stdio 
 - [] a2a integration
  - [] have jacs cli installed along with wheel
   - [] python based instructions for how to create - cli create agent 
      1. cli create agent 
      2. config jacspy to load each agent
 - [] github actions builder for linux varieties
 - [] switch to uv from pip/etc

### JACS core
 
 - [] brew installer, review installation instrucitons,  cli install instructions. a .sh command?
 - [] more a2a tests
 - [] ensure if a user wants standard logging they can use that

 
 - [] register agent
 - [] remove requirement to store public key type? if detectable
 - [] upgrade pqcrypto https://github.com/rustpq/pqcrypto/issues/79
 - [] diff versions
 - [] bucket integration
 - [] RBAC integration with header
 - [] clean io prepping for config of io

 ### minor core
- [] don't store  "jacs_private_key_password":  in config, don't display
- [] minor feature - no_save = false should save document and still return json string instead of message on create document
 - [] default to dnssec if domain is present - or WARN

### jacsmcp

 - [] prototype

### jacspy

- [] refactor api
- [] publish to pipy 
- [] tracing and logging integration tests


### jacsnpm

- [] publish to npm
- [] tracing and logging integration tests


==== 
## 0.3.6

### Security

- **[CRITICAL] Fixed key derivation**: Changed from single SHA-256 hash to proper PBKDF2-HMAC-SHA256 with 100,000 iterations for deriving encryption keys from passwords. The previous single-hash approach was vulnerable to brute-force attacks.

- **[CRITICAL] Fixed crypto panic handling**: Replaced `.expect()` with proper `.map_err()` error handling in AES-GCM encryption/decryption. Crypto failures now return proper errors instead of panicking, which could cause denial of service.

- **[HIGH] Fixed foreign signature verification**: The `verify_wrapped_artifact` function now properly returns `Unverified` status for foreign agent signatures when the public key is not available, rather than incorrectly indicating signatures were verified. Added `VerificationStatus` enum to explicitly distinguish between `Verified`, `SelfSigned`, `Unverified`, and `Invalid` states.

- **[HIGH] Fixed parent signature verification**: The `verify_parent_signatures` function now actually verifies parent signatures recursively. Previously it always returned true regardless of verification status.

- Added `serial_test` for test isolation to prevent environment variable conflicts between tests.

- Added `regenerate_test_keys.rs` utility example for re-encrypting test fixtures with the new KDF.

- **[MEDIUM] Fixed jacsnpm global singleton**: Refactored from global `lazy_static!` mutex to `JacsAgent` NAPI class pattern. Multiple agents can now be used concurrently in the same Node.js process. Legacy functions preserved for backwards compatibility but marked deprecated.

- **[MEDIUM] Fixed jacspy global singleton**: Refactored from global `lazy_static!` mutex to `JacsAgent` PyO3 class pattern. Multiple agents can now be used concurrently in the same Python process. The `Arc<Mutex<Agent>>` pattern ensures thread-safety and works with Python's GIL as well as future free-threading (Python 3.13+). Legacy functions preserved for backwards compatibility.

- **[MEDIUM] Added secure file permissions**: Private keys now get 0600 permissions (owner read/write only) and key directories get 0700 (owner rwx only) on Unix systems. This prevents other users on shared systems from reading private keys.

### devex
- [x] add updates to book
- [x] add observability demo

### jacs
 - [x] a2a integration
- [x] clean up observability
   - Observability: added feature-gated backends (`otlp-logs`, `otlp-metrics`, `otlp-tracing`) and optional `observability-convenience`. Default build is minimal (stderr/file logs only), no tokio/OpenTelemetry; clear runtime errors if a requested backend isn’t compiled. Docs now include a feature matrix and compile recipes. Tests updated and all pass with features.

 - [x] dns verification of pubic key hash
      - DNS: implemented fingerprint-in-DNS (TXT under `_v1.agent.jacs.<domain>.`), CLI emitters for BIND/Route53/Azure/Cloudflare, DNSSEC validation with non-strict fallback, and config flags (`jacs_agent_domain`, `jacs_dns_validate`, `jacs_dns_strict`, `jacs_dns_required`). Added CLI flags `--require-dns`, `--require-strict-dns`, `--ignore-dns`, and `--no-dns` (alias preserved). Improved error messages, updated docs, and added policy/encoding tests.

 
 - [x] scaffold private key bootstrapping with vault, kerberos - filesystem





--------------------

## 0.3.5

- [x] Update documentation.

### JACS core

 - [x] add timestamp to prevent replay attacks to request/response features
 - [x] make cli utils available to other libs
 - [x] *** start effort to channel all logging to jacs -> open telemetry -> fs or elsewhere that doesn't write to stdio on 
    1. the main traffic for sign and verify
    2. all logs generated

### jacspy

 - [x] install python mcp libs with the python wheel, use python loader to extend/export jacs.so

## jacsnpm

proof of concept

 - [x] scaffold
 - [x] use refactored agent trait instead of replicating
 - [x] typescript mcp client and server tests
 - [x]  test sse mcp client and server
 - [x]  node express middleware


--------------------

# COMPLETED

## 0.3.4

## integrated demo

 - [x] sign request/response (any python object -> payload)
 - [x] verify response/request (any payload json string -> python object)
 - [x] integrate with fastMCP, MCP, and Web for request response
 - [x] have identity available to business logic
 - [x] have logs available for review (no writing to file, ephemoral)

## jacspy

 - [x] make decorator for easy use in @tools
 - [x] new local builder
 - [x] fastmcp client and server sse
 - [x] jacspy test -  sign(content) -> (signature, agentid, agentversion, documentid, documentversion)
 - [x] jacspy test - verify(content, signature, agentid, agentversion) -> bool, error

 
 ### General 

 - init √
 - [x] load(config) -> Agent
 
### detailed
 - [x] make sure config directory is in isolated location, like with key
 - [x] make config and security part of Agent
 - [x] don't use env  everywhere- dep jacspy
   - [x] load multistorage into agent object to re-use
   - [x] BUG keys directory isolation broken when re-using Multistorage. TODO wrap key saving in different function
   - [x] don't use set_env_vars() by default - may be more than one agent in system    
   - [x] change config to have storagetype string, add to config schema
   - write tests for no env vars usage of config
   - load by id from default store
   - [x] don't store passwords in config
   - [x] all old tests and some new tests pass
- [x] cli init function
 - [x] clean up fs defaults in init/config/ 
 - [x] bug with JACS_SCHEMA_AGENT_VERSION didn't have default on cli init
 - [x] separate JACS readme repo readme
 - [x] minimal github actions
 - [x] autodetect public key type
 - [x] refactor API so easier to use from higher level libraries  - create agent, load agent, save document, create document, update document, sign 
   init, load agent, verify agent, verify document, 
   - [x] single init, also signs agent
   - [x] load from config
   - [x] have load agent from config also load keys IF SIGNED

 
 

---------------

# 0.3.3

## jacs 0.3.3
 - [x] change project to workspace
 - [x] basic python integration
 - [x] upgraded to edition = "2024" rust-version = "1.85"
 - [x] separate public key location from private key location
 - [x] cli review and tests 
 - [x] TEST init agent without needing configs in filesystem by checking that needed ENV variables are set

## 0.3.2
 - [x] add common clause to Apache 2.0
 - [x] use a single file to handle file i/o for all storage types
 - [x] use an ENV wrapper to prep for wasm
 - [x] complete migration away from fs calls except for config, security, tests, cli 
 - [x] create tests using custom schemas - verify this is working


## 0.3.1
- [x] upgraded many dependencies using 
    cargo install cargo-edit
    cargo upgrade
    
## 0.3.0
- added jacsType - free naming, but required field for end-user naming of file type, with defaults to "document"
- TODO update jsonschema library
- updated strum, criterion
- updated reqwest library
- fixed bug EmbeddedSchemaResolver not used for custom schemas
- added load_all() for booting up  
- WIP move all fileio to object_store 
- WIP way to mark documents as not active - separate folder, or just reference them from other docs
- fixed issue with filepaths for agents and keys
- added jacsType to to jacs document as required
- added archive old version, to move older versions of docs to different folder
- added jacsEmbedding to headers, which allow persistance of vector embeddings iwth jacs docs. 
- default to only loading most recent version of document in load_all
- fixed bug with naming file on update
- changes to message schema to always include header
- add jacsLevel to track general type of document and its mutability

## 0.2.13
- save public key to local fs
- restricted signingAlgorithm in schema
- refresh schema for program, program node/consent/action/tool

## 0.2.12

- Let Devin.ai have a go at looking for issues with missing documentation, unsafe calles, and uncessary copies of data, updated some libs
- Fixed an issue with the schema resolver to handle more cases in tests.


## 0.2.11

- bringing some documentation up to date
- adding evaluations schemas
- adding agree/disagree to signature
- adding evaluation helpers **
- incremental documentation work **
- make github repo public **
- proper cargo categories

## 0.2.10

- decouple message from task so they can arrive out of order. can be used to create context for task
- parameteraize agreement field
- task start and end agreements functions
- fixed issue with schema path not being found, so list of fields returned incorrect
- retrieve long and short schema name from docs - mostly for task and agent


## 0.2.9

- tests for task and actions creation
- handle case of allOf in JSON schema when recursively retrieving "hai" print level
- add message to task
- fixed issue with type=array/items in JSON schema when recursively retrieving "hai" print level


## 0.2.8

 - add question and context to agreement, useful to UIs and prompting
 - adding "hai", fields to schema denote which fields are useful for agents "base", "meta", "agent"

## 0.2.7

 - crud operations for agent, service, message, task - lacking tests
 - more complete agent and cli task creation

## 0.2.6
 - doc include image


## 0.2.5
 - filesystem security module
 - unit, action, tool, contact, and service schemas
 - tasks and message schemas

## 0.2.4

- add jacsRegistration signature field
- add jacsAgreement field
- tests for issue with public key hashing because of \r
- add agreement functions in trait for agent
- fixes with cli for agent and config creation


## 0.2.3

 - add config creation and viewing to CLI
 - added gzip to content embedding
 - added extraction for embedded content
 - started mdbook documentation


## 0.2.2 - April 12 2024

 - prevent name collisions with jacs as prefix on required header fields
 - add "jacsFiles" schema to embed files or sign files that can't be embedded



## 0.2.1

 - build cli app (bulk creation and verification) and document
 - encrypt private key on disk

## 0.2.0

 - encrypt private key in memory, wipe
 - check and verify signatures
 - refactors
 - allow custom json schema verification