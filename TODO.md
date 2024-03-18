## todo

### critical

DOCUMENT


 - change document and/or copy
 - diff document
 - sign document  **


  - load document
 - save document




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

 - create agent
 - update agent

 - create permission
  - [ ] decide params
  - [ ]


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


use serde_json::Value;
use std::collections::HashMap;

fn main() {
    let mut map: HashMap<String, Value> = HashMap::new();

    // Insert values into the map
    map.insert("user:1".to_string(), Value::String("Alice".to_string()));
    map.insert("user:2".to_string(), Value::String("Bob".to_string()));
    map.insert("product:1".to_string(), Value::Number(10.into()));
    map.insert("product:2".to_string(), Value::Number(20.into()));

    // Retrieve values based on a key prefix
    let prefix = "user:";
    let user_values: HashMap<&String, &Value> = map
        .iter()
        .filter(|(key, _)| key.starts_with(prefix))
        .collect();

    // Print the retrieved values
    for (key, value) in &user_values {
        println!("Key: {}, Value: {}", key, value);
    }
}


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