use crate::crypt::hash::hash_string as crypt_hash_string;
use serde_json::Value;
/// abstract traits that must be implemented by importing libraries
pub trait SignatureVerifiers {
    fn hash_string(&self, input_string: &str) -> String;
    fn get_array_of_values(&self, signature: serde_json::Value, fieldname: &str) -> String;
}

impl SignatureVerifiers for super::Schema {
    fn hash_string(&self, input_string: &str) -> String {
        crypt_hash_string(input_string)
    }

    /// utilty function to retrieve the list of fields
    /// this is especially useful for signatures
    fn get_array_of_values(&self, signature: serde_json::Value, fieldname: &str) -> String {
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
