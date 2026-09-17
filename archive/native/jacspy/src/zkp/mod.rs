
use bulletproofs::r1cs::{Prover, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::scalar::Scalar;
use serde_json::Value;

// Define the JSON schema
let schema = r#"
{
  "type": "object",
  "properties": {
    "name": { "type": "string" },
    "age": { "type": "integer", "minimum": 18 },
    "credits": { "type": "integer", "minimum": 1000, "maximum": 10000 }
  },
  "required": ["name", "age", "credits"]
}
"#;

// Parse the JSON document
let json_str = r#"
{
  "name": "John Doe",
  "age": 25,
  "credits": 5000
}
"#;
let json_value: Value = serde_json::from_str(json_str).unwrap();

// Generate Bulletproofs generators
let pc_gens = PedersenGens::default();
let bp_gens = BulletproofGens::new(64, 1);

// Create a Prover
let mut prover = Prover::new(&bp_gens, &pc_gens, &mut rand::thread_rng());

// Prove that the JSON document adheres to the schema
let schema_result = prover.prove_json_schema(&json_value, schema);
assert!(schema_result.is_ok());

// Prove that the "credits" field is within the specified range
let credits_value = json_value["credits"].as_i64().unwrap();
let (credits_commitment, credits_proof) = prover.prove_range(credits_value, 1000, 10000).unwrap();

// Serialize the proofs
let schema_proof = schema_result.unwrap();
let serialized_schema_proof = serde_json::to_string(&schema_proof).unwrap();
let serialized_credits_proof = serde_json::to_string(&credits_proof).unwrap();

// // Create a Verifier
// let mut verifier = Verifier::new(&bp_gens, &pc_gens);

// // Verify the schema proof
// let deserialized_schema_proof: Vec<u8> = serde_json::from_str(&serialized_schema_proof).unwrap();
// let schema_result = verifier.verify_json_schema(&json_value, schema, &deserialized_schema_proof);
// assert!(schema_result.is_ok());

// // Verify the credits range proof
// let deserialized_credits_proof: RangeProof = serde_json::from_str(&serialized_credits_proof).unwrap();
// let credits_result = verifier.verify_range(&credits_commitment, &deserialized_credits_proof, 1000, 10000);
// assert!(credits_result.is_ok());


use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::scalar::Scalar;
use serde_json::Value;

// Parse the JSON document
let json_str = r#"
{
  "name": "John Doe",
  "age": 25,
  "credits": 5000
}
"#;
let json_value: Value = serde_json::from_str(json_str).unwrap();

// Generate Bulletproofs generators
let pc_gens = PedersenGens::default();
let bp_gens = BulletproofGens::new(64, 1);

// Server-side: Prove that the "credits" field is within the specified range
let mut prover = Prover::new(&bp_gens, &pc_gens, &mut rand::thread_rng());
let credits_value = json_value["credits"].as_i64().unwrap();
let (credits_commitment, credits_proof) = prover.prove_range(credits_value, 1000, 10000).unwrap();

// Serialize the range proof
let serialized_credits_proof = serde_json::to_string(&credits_proof).unwrap();

// Client-side: Verify the credits range proof
let mut verifier = Verifier::new(&bp_gens, &pc_gens);
let deserialized_credits_proof: RangeProof = serde_json::from_str(&serialized_credits_proof).unwrap();
let credits_result = verifier.verify_range(&credits_commitment, &deserialized_credits_proof, 1000, 10000);
assert!(credits_result.is_ok());