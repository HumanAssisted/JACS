## todo

### document signing

NEEDS TESTS

 ## Integration of signatures ---------------------

 - more configurable key loading tests
 - verify public key used with hash
 - load forieing public signature for doc
 - test verify signature of agent
 - test verify signature of doc



### AGENT REGISTRATION ---------------------

 - schema
  - update registration to be signature and reserved word.
  - name of registrar
  - public key location/url
  - public key hash


 ### document permissions ---------------------

 punt for server

 - default permissions
 - access permissions
 - sign access permissions
 - modify access permissions
 - verify access permissions on edit, read
 - get fields and data that user has access to


  --------------------------------------------------------

### debt

 - threadsafe logging
 - better error wrapping
 - refactor to re-use DRY
 - more thread safety agent values
 - signature stuff
  - [ ] load with password
  - [ ] save with password
  - [ ] decide params (
            fields, check they are present
  - [ ] verify and teset standard CONCAT function for field values/types

 - move encryption to trait that can be loaded

### MVP

 - how does the regsitrar work?
  - one registrar
  - registrar schema (list of endpoints, public key signature)

 - outline functions
 - outline traits
   - allow overwrite of defaults for file loading of keys, local agent
   - load local agent (string or id)
   - load local foriegn agent (string, or id)
   - load remote foreign agent (id)
   - load keys to agent
   - verifiy agent
   - verify agent regsistaration
   - verify doc registration
   - verify doc
   - register agent
   - register document

   - save doc/agent, remote local
   - load doc by id local
   - load doc by string
   - edit and sign doc
   - diff edit
   - sign doc
   - save doc


 - version not updated until everything signed
 - signature verification
 - add signature types enum so implementations can check
 - auto doc rust
 - push docs github pages



  --------------------------------------------------------
 # DONE
  --------------------------------------------------------
NEEDS TESTS
 - self sign agent
 - verify signature header
 - get fields needed for signature from signature types
 - create or verify signature
 - sign documents
- hard code keys which are signatures for self signing
- make sure signature field doesn't use forbidden fields like sha256 and itself
 - set base directory
  - agent key default storage
 - agent key loading
 - sha of public key in every signature as part of schema, require it in schema
- sign every creation or update
  - [ ] create schema snippet with sig
  - [ ] add signature to doc signature (overwrite)


 - check signature(s) of version
  - every admin or all admin
     - retrieve proper signature
     - [ ] select fields
     - [ ] select fields


 ### crud

 - sign every version on default fields, to default field

  - agent key creation
  - test create signature from string
  - agent update version and validate (version self)
 - agent update version and validate
  - document copy , hash, validate, and store
 - document edit - copy, add fields, diff, hash, validate, store
  - remove document
- new document with custom schema - validate and store
 - list stored documents
  - load document and store
 - load doucment with custom schema - validate and store
  - return id and version on actor,
 -  document return id and version on create
