use serde_json::Value;
use sha2::{Digest, Sha256};

/// abstract traits that must be implemented by importing libraries
pub trait SignatureVerifiers {
    fn hash_string(&self, input_string: &String) -> String;
    fn get_array_of_values(&self, signature: serde_json::Value, fieldname: &String) -> String;
}

impl SignatureVerifiers for super::Schema {
    fn hash_string(&self, input_string: &String) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input_string.as_bytes());
        let result = hasher.finalize();
        let hash_string = format!("{:x}", result);
        return hash_string;
    }

    /// utilty function to retrieve the list of fields
    /// this is especially useful for signatures
    fn get_array_of_values(&self, signature: serde_json::Value, fieldname: &String) -> String {
        if let Some(array_field) = signature.get(fieldname).and_then(Value::as_array) {
            let mut result_strings = Vec::new();
            for value in array_field {
                if let Some(string_value) = value.as_str() {
                    result_strings.push(string_value.to_string());
                }
            }
            return format!("Result Strings: {:?}", result_strings);
        }
        "".to_string()
    }
}
