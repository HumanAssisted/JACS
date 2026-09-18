I have an architectural problem with JACS. 

1. I likely have un-needed memory storage as part of the agent (.documents, this is probably uneeded)  and export functions for the agent as DocumentTraits (this is fine)
2. I use object_storage used via multistorage in storage/mod.rs instead of it being an agent trait, it's runtime configurable export ()

By design JACS is meant to return the raw strings or json objects for higher level libraries. 

It writes out to disk by default in tests because of configuration, but even theoretically supports wasm


1.  not store jacs documents memory if the user didn't want that. Schemas can be in memory. I guess this means moving the DocumentTraits to multistorage??

2. some potentially new functions are listed below. These require the storage to do some computation either befor or after actually storing. For example , JACS already will verify signatures and JSON schemas. 

 - get_document_ids_by_agent(document_id) -> list of document_ids, 
 - get_document_all_versions(document_id) -> list of document_versions,
 - get_document_latest(document_id) -> on a tree of document versions and their predecesor, get the latest version
 - merge_documents(document_id, version_one, version_two)

 For now we can have placeholders for these. 

 3.   documenttraits or multistorage will also need retrieval from other databases


Read the code very carefully. Understand the intent of the functions I am requesting and make a plan we can implement in a subsequent step. We want to make the code more DRY and have the absractions be more useful. Theses are the lowest level storage functions, and what we want to be able to do is use these to build other functionality on top like build indexes, operate over multiple documents, etc. 

Be explicity in your plan, stating why you would make the changes to better align with the design goals. 
Be succinct and efficient. 
 
Keep in mind, all the tests must pass without modification after these changes. 

=======

I'll analyze the JACS architecture to understand the current storage design and propose a plan to address your concerns. Let me start by examining the relevant code.

[10 tools called]

Now I'll analyze the architectural plan based on my understanding of the code:

## Architectural Analysis and Plan for JACS Storage Refactoring

### Current State Analysis:

1. **Memory Storage Issue**: The Agent struct contains `documents: Arc<Mutex<HashMap<String, JACSDocument>>>` which stores all loaded documents in memory. This is unnecessary when users might want disk-only or other storage backends.

2. **Storage Design**: MultiStorage is correctly positioned as a pluggable storage backend, but DocumentTraits methods are implemented on Agent, mixing storage concerns with agent logic.

3. **Separation of Concerns**: Storage operations are scattered between:
   - Agent's in-memory HashMap
   - FileLoader trait methods (fs_document_save, fs_docs_load_all, etc.)
   - DocumentTraits implementations on Agent

### Proposed Plan:

#### 1. **Move DocumentTraits to MultiStorage**
**Why**: This aligns with JACS's design principle of returning raw strings/JSON. Storage should handle document persistence, not the Agent.

**Changes**:
- Create a new trait `StorageDocumentTraits` in storage/mod.rs
- Move all document storage/retrieval methods from DocumentTraits to this new trait
- Keep only signature/validation methods in DocumentTraits (on Agent)

#### 2. **Remove In-Memory Document Storage from Agent**
**Why**: Memory usage should be opt-in, not default. Users should decide if they want caching.

**Changes**:
- Remove `documents: Arc<Mutex<HashMap<String, JACSDocument>>>` from Agent
- Add optional in-memory caching layer to MultiStorage
- Make document retrieval always go through storage

#### 3. **Implement New Storage Methods**
**Why**: These enable higher-level operations while keeping storage concerns centralized.

**New methods in StorageDocumentTraits**:
```rust
trait StorageDocumentTraits {
    // Existing methods moved from DocumentTraits
    fn store_document(&self, doc: &JACSDocument) -> Result<(), Box<dyn Error>>;
    fn get_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>>;
    fn remove_document(&self, key: &str) -> Result<JACSDocument, Box<dyn Error>>;
    fn list_documents(&self, prefix: &str) -> Result<Vec<String>, Box<dyn Error>>;
    
    // New methods for advanced queries
    fn get_documents_by_agent(&self, agent_id: &str) -> Result<Vec<String>, Box<dyn Error>>;
    fn get_document_versions(&self, document_id: &str) -> Result<Vec<String>, Box<dyn Error>>;
    fn get_latest_document(&self, document_id: &str) -> Result<JACSDocument, Box<dyn Error>>;
    fn merge_documents(&self, doc_id: &str, v1: &str, v2: &str) -> Result<JACSDocument, Box<dyn Error>>;
}
```

#### 4. **Refactor FileLoader Integration**
**Why**: FileLoader methods should use StorageDocumentTraits, not direct storage access.

**Changes**:
- FileLoader methods call StorageDocumentTraits methods
- Remove direct storage.save_file/get_file calls for documents
- Keep raw file operations for non-document files

#### 5. **Maintain Test Compatibility**
**Why**: Tests shouldn't change - this is an internal refactoring.

**Strategy**:
- Agent still implements DocumentTraits but delegates to storage
- Keep same public API surface
- Tests continue using agent.load_document(), agent.get_document(), etc.

### Implementation Steps:

1. **Phase 1**: Create StorageDocumentTraits in MultiStorage
   - Add trait definition with placeholder implementations
   - Add optional in-memory cache to MultiStorage

2. **Phase 2**: Move storage logic from Agent to MultiStorage
   - Implement StorageDocumentTraits methods
   - Update Agent to delegate to storage

3. **Phase 3**: Remove Agent's document HashMap
   - Update all references to use storage
   - Ensure tests still pass

4. **Phase 4**: Implement new query methods
   - Add indexing support for efficient queries
   - Implement version tree traversal for get_latest_document

### Benefits:
- **DRY**: Storage logic centralized in one place
- **Flexible**: Users can choose storage backends without memory overhead
- **Extensible**: New storage methods can be added without touching Agent
- **Testable**: Storage can be mocked/tested independently
- **WASM-friendly**: No forced memory usage, works with WebLocalStorage

This plan maintains backward compatibility while making the architecture more modular and aligned with JACS's design goals of being a low-level library that returns raw data.

====================
That looks like a good plan. One clarification before we start. Fileloader/fs_document_save might need to be a special case saving and loading keys in the CLI. Could you please research how keys can be saved and loaded, and if maybe we should keep them?
====================
 I'll investigate how keys are saved and loaded in JACS to understand if FileLoader methods need special handling for cryptographic keys.

[8 tools called]

Based on my research, here's what I found about key management in JACS:

## Key Management Analysis

### Key Storage Structure:
1. **Keys are stored separately from documents**: 
   - Keys use `make_key_directory_path()` → `{jacs_key_directory}/{filename}`
   - Documents use `make_data_directory_path()` → `{jacs_data_directory}/{filename}`

2. **Key-specific FileLoader methods**:
   - `fs_save_keys()` - Saves agent's private/public keys
   - `fs_load_keys()` - Loads agent's keys from disk
   - `fs_preload_keys()` - Loads custom keys
   - `fs_load_public_key()` - Loads remote agent public keys
   - `fs_save_remote_public_key()` - Saves other agents' public keys
   - `save_private_key()` - Handles encryption of private keys
   - `load_private_key()` - Handles decryption of private keys

3. **Key operations are critical for**:
   - Agent creation (`generate_keys()`)
   - Agent loading (needs keys for signatures)
   - Document signing/verification
   - Cross-agent communication

### Updated Plan Clarification:

**We should KEEP FileLoader methods for key management** because:
1. Keys have different storage requirements (separate directory, encryption)
2. Keys are not documents - they're binary data with special handling
3. CLI heavily relies on these for agent creation and operation
4. Keys need encryption/decryption logic that doesn't apply to documents

**Revised approach**:
1. **Keep FileLoader trait** but split it into:
   - `KeyFileLoader` - for key operations (keep all key methods)
   - `StorageDocumentTraits` - for document operations (move from DocumentTraits)

2. **fs_document_save can be moved** to StorageDocumentTraits since it's just saving document JSON

3. **Keep these FileLoader methods**:
   - All key-related methods
   - `make_key_directory_path()` 
   - `check_data_directory()`, `check_key_directory()`
   - File utility methods like `create_backup()`, `mark_file_not_executable()`

4. **Move to StorageDocumentTraits**:
   - `fs_document_save()`
   - `fs_docs_load_all()`
   - `fs_agent_save()` / `fs_agent_load()`
   - `fs_document_archive()`
   - `fs_get_document_content()`

This separation makes sense because:
- Keys are infrastructure (like config files)
- Documents are application data
- Different storage backends might handle documents differently but keys should always be local files for security

Would you like me to proceed with this refined plan that preserves key management in FileLoader while moving document operations to the new storage trait?

====

Ok, let's proceed with the first step in your plan to move DocumentTraits to MultiStorage 