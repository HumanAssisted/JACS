use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

// --- Data Structures ---

/// Represents a stored document (immutable record) on the network.
/// The document could be for the public key, recovery code signature, or any other immutable item.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Document {
    /// Agent identifier with version (e.g. "agent_id:version")
    pub agent_id: String,
    /// Document identifier (for instance, "public_key" or "recovery_code")
    pub document_id: String,
    /// The value stored (e.g. the public key encoded as hex, or the recovery code)
    pub value: String,
    /// A digital signature over the value (or over the record) in hex
    pub signature: String,
}

/// Simulated key–value store. In a real implementation this would be replaced by a libp2p DHT.
pub struct KVStore {
    pub store: HashMap<String, Document>,
}

impl KVStore {
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }
    
    /// Simulate writing a document to the network.
    /// In our model, every write is validated by the signature.
    pub fn write_document(&mut self, doc: Document) -> bool {
        // For simplicity, we reject if the document_id already exists.
        if self.store.contains_key(&doc.document_id) {
            println!("Document {} already exists.", doc.document_id);
            return false;
        }
        self.store.insert(doc.document_id.clone(), doc);
        true
    }
    
    /// Returns the stored signature for a given document.
    pub fn get_signature(&self, document_id: &str) -> Option<String> {
        self.store.get(document_id).map(|doc| doc.signature.clone())
    }
    
    /// Returns the stored public key (as a hex string) for an agent document.
    pub fn get_public_key(&self, agent_doc_id: &str) -> Option<String> {
        self.store.get(agent_doc_id).map(|doc| doc.value.clone())
    }
}

/// Represents an agent’s key material.
pub struct Agent {
    /// The immutable agent id with version (e.g. "agent_id:1")
    pub id: String,
    /// The agent’s current keypair.
    pub keypair: Keypair,
    /// A large recovery code (random string)
    pub recovery_code: String,
    /// The signature (by the private key) of the recovery code.
    pub recovery_signature: Signature,
}

// --- Helper Functions ---

/// Generate a large recovery code as a random 64-character hexadecimal string.
fn generate_large_recovery_code() -> String {
    let mut rng = rand::thread_rng();
    let code: [u8; 32] = rng.gen();
    hex::encode(code)
}

/// Given a public key and a recovery code, produce a placeholder “signature”
/// for updating the agent’s public key. In a real system, this would be a proper cryptographic signature.
fn new_public_key_signature_placeholder(new_public_key: &PublicKey, recovery_code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(new_public_key.to_bytes());
    hasher.update(recovery_code.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

// --- Core Functions ---

/// Creates a new agent account.
/// 1. Generates a keypair and a large recovery code.
/// 2. Signs the recovery code with the private key.
/// 3. Writes both the public key and the recovery signature to the network.
pub fn create_agent(kv: &mut KVStore) -> Agent {
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    
    // For the agent id, we use the hex of the public key and append version 1.
    let pub_key_bytes = keypair.public.to_bytes();
    let agent_id = format!("{}:1", hex::encode(&pub_key_bytes));
    
    // Generate a recovery code and sign it with the private key.
    let recovery_code = generate_large_recovery_code();
    let recovery_signature = keypair.sign(recovery_code.as_bytes());
    
    // Write the public key record.
    let pub_key_doc = Document {
        agent_id: agent_id.clone(),
        document_id: format!("{}:public_key", agent_id),
        value: hex::encode(&pub_key_bytes),
        // Sign the public key (here we sign the raw bytes; in practice, include metadata as needed).
        signature: hex::encode(keypair.sign(&pub_key_bytes).to_bytes()),
    };
    kv.write_document(pub_key_doc);
    
    // Write the recovery code signature record.
    let recovery_doc = Document {
        agent_id: agent_id.clone(),
        document_id: format!("{}:recovery_code", agent_id),
        value: recovery_code.clone(),
        signature: hex::encode(recovery_signature.to_bytes()),
    };
    kv.write_document(recovery_doc);
    
    Agent { id: agent_id, keypair, recovery_code, recovery_signature }
}

/// Updates an agent’s public key using the recovery code.
/// The function expects:
/// - the current agent_id (with version),
/// - the recovery code provided by the agent,
/// - the new public key,
/// - and (as a placeholder) a signature of the new public key generated using the recovery code.
/// In a real implementation this signature would be generated via a secure recovery mechanism.
pub fn update_agent(
    agent: &Agent,
    new_public_key: PublicKey,
    kv: &mut KVStore,
    provided_recovery_code: &str,
) -> bool {
    // Look up the stored recovery document.
    let recovery_doc_id = format!("{}:recovery_code", agent.id);
    let stored_recovery_doc = kv.store.get(&recovery_doc_id);
    
    if stored_recovery_doc.is_none() {
        println!("No recovery document found for agent.");
        return false;
    }
    let stored_doc = stored_recovery_doc.unwrap();
    
    // Verify the provided recovery code matches the stored one.
    if stored_doc.value != provided_recovery_code {
        println!("Recovery code mismatch.");
        return false;
    }
    
    // For this update, we assume that possession of the recovery code authorizes the key change.
    // Increment the version number.
    let parts: Vec<&str> = agent.id.split(':').collect();
    if parts.len() != 2 {
        println!("Invalid agent id format.");
        return false;
    }
    let version: u64 = parts[1].parse().unwrap_or(1);
    let new_version = version + 1;
    
    // Define the new agent id based on the new public key and new version.
    let new_pub_key_bytes = new_public_key.to_bytes();
    let new_agent_id = format!("{}:{}", hex::encode(&new_pub_key_bytes), new_version);
    
    // Produce a placeholder signature for the new public key using the recovery code.
    let new_pk_sig = new_public_key_signature_placeholder(&new_public_key, provided_recovery_code);
    
    // Write the new public key record to the network.
    let pub_key_doc = Document {
        agent_id: new_agent_id.clone(),
        document_id: format!("{}:public_key", new_agent_id),
        value: hex::encode(&new_pub_key_bytes),
        signature: new_pk_sig,
    };
    kv.write_document(pub_key_doc)
}

/// Retrieves the signature of a stored document by its document_id.
pub fn get_signature(kv: &KVStore, document_id: &str) -> Option<String> {
    kv.get_signature(document_id)
}

/// Retrieves the public key for an agent from its public_key document.
pub fn get_public_key(kv: &KVStore, agent_doc_id: &str) -> Option<String> {
    kv.get_public_key(agent_doc_id)
}

// --- Example Main Function ---

fn main() {
    // In a real system, this KV store would be the libp2p DHT.
    let mut kv_store = KVStore::new();
    
    // Create a new agent.
    let agent = create_agent(&mut kv_store);
    println!("Created agent with id: {}", agent.id);
    
    // Retrieve and print the public key from the network.
    let pub_doc_id = format!("{}:public_key", agent.id);
    if let Some(pub_key_hex) = get_public_key(&kv_store, &pub_doc_id) {
        println!("Stored public key: {}", pub_key_hex);
    }
    
    // Retrieve and print the recovery signature.
    let rec_doc_id = format!("{}:recovery_code", agent.id);
    if let Some(rec_sig) = get_signature(&kv_store, &rec_doc_id) {
        println!("Stored recovery signature: {}", rec_sig);
    }
    
    // Simulate updating the agent's public key.
    let mut csprng = OsRng {};
    let new_keypair = Keypair::generate(&mut csprng);
    let update_result = update_agent(&agent, new_keypair.public, &mut kv_store, &agent.recovery_code);
    println!("Update agent result: {}", update_result);
    
    // After update, try retrieving the new public key.
    // Note: In this sketch, the new agent id is based on the new public key.
    let new_agent_id = format!("{}:{}", hex::encode(new_keypair.public.to_bytes()), {
        let parts: Vec<&str> = agent.id.split(':').collect();
        let version: u64 = parts[1].parse().unwrap_or(1);
        version + 1
    });
    let new_pub_doc_id = format!("{}:public_key", new_agent_id);
    if let Some(new_pub_key_hex) = get_public_key(&kv_store, &new_pub_doc_id) {
        println!("New stored public key: {}", new_pub_key_hex);
    }
}
