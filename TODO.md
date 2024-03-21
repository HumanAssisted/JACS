## todo

### document signing

- hard code keys which are signatures for self signing
- make sure signature field doesn't use forbidden fields like sha256 and itself
- sha of public key in every signature as part of schema, require it in schema
- sign every creation or update

NEEDS TESTS

 - agent key creation
 - test create signature from string
 - test verify signature from string

 ## Integration of signatures ---------------------

 - verify signature header
 - get fields needed for signature from signature types
 - create or verify signature
 - sign documents

 DONE ABOVE, but TESTING



 - sign every version on default fields, to default field


 - self sign agent
 - update agent on version change requires some thinking, save self?
 - on key creation save self?




 - add public key signature to agent so users can verify public key
 - sign document  **
 - check signature public keys hashmap

 ### document permissions ---------------------

 - default permissions
 - access permissions
 - sign access permissions
 - modify access permissions
 - verify access permissions on edit, read
 - get fields and data that user has access too


### AGENT REGISTRATION ---------------------

 - schema
  - name of registrar
  - public key location/url
  - public key hash
  - registars public key signature
  - registars signature schema

  --------------------------------------------------------

### debt

 - logging
 - error wrapping
 - refactor to re-use DRY

 - more thread safety agent values



 - ** create signature function for versionSignature
  - [ ] load with password
  - [ ] save with password
  - [ ] decide params (
            fields, check they are present

            )
  - [ ] select fields
  - [ ] standard CONCAT function
  - [ ] generate sig with private key
  - [ ] change versions
  - [ ] create schema snippet with sig
  - [ ] add signature to doc signature (overwrite)


 - check signature(s) of version
  - every admin or all admin
     - retrieve proper signature
     - [ ] select fields
     - [ ] select fields



### MVP

 - how does the regsitrar work?
  - one registrar
  - registrar schema (list of endpoints, public key signature)



### cleanup
 - move encryption to trait that can be loaded



 - how are documents loaded and verfied
   - load doc and store within agent. Vector<Value> KEY - id:version
   - verify every doc has passes the header, otherwise its not JACS doc
   - load schema for the document types
   - verify doc schema
   - verify signature




 - local schema resolver from buffer/hashmap
 - traits



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


 # DONE
  --------------------------------------------------------
NEEDS TESTS
 - set base directory
  - agent key default storage
 - agent key loading

 ### crud
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
