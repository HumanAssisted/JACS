//! Common type conversion utilities for bindings.
//!
//! This module provides shared functionality for converting between
//! language-native types and serde_json::Value. Bindings use these
//! helpers along with their language-specific conversion code.

use base64::{Engine as _, engine::general_purpose};
use serde_json::{Map as JsonMap, Value};

/// Marker key for specially encoded types in JSON objects.
pub const TYPE_MARKER_KEY: &str = "__type__";
/// Data key for specially encoded types in JSON objects.
pub const DATA_KEY: &str = "data";
/// Type marker for bytes/buffer data.
pub const TYPE_BYTES: &str = "bytes";
/// Type marker for Node.js Buffer data.
pub const TYPE_BUFFER: &str = "buffer";

/// Check if a JSON object represents specially encoded bytes.
///
/// Returns the decoded bytes if the object has the correct structure,
/// or None if it's a regular object.
pub fn try_decode_bytes_object(obj: &serde_json::Map<String, Value>) -> Option<Vec<u8>> {
    if let (Some(Value::String(type_str)), Some(Value::String(data))) =
        (obj.get(TYPE_MARKER_KEY), obj.get(DATA_KEY))
    {
        if type_str == TYPE_BYTES || type_str == TYPE_BUFFER {
            return general_purpose::STANDARD.decode(data).ok();
        }
    }
    None
}

/// Encode bytes as a JSON object with type marker.
///
/// This creates a portable representation that can be decoded on any platform.
pub fn encode_bytes_as_json(bytes: &[u8], type_marker: &str) -> Value {
    let base64_str = general_purpose::STANDARD.encode(bytes);
    let mut map = JsonMap::new();
    map.insert(TYPE_MARKER_KEY.to_string(), Value::String(type_marker.to_string()));
    map.insert(DATA_KEY.to_string(), Value::String(base64_str));
    Value::Object(map)
}

/// Encode bytes using the Python-style marker ("bytes").
pub fn encode_bytes_python(bytes: &[u8]) -> Value {
    encode_bytes_as_json(bytes, TYPE_BYTES)
}

/// Encode bytes using the Node.js-style marker ("buffer").
pub fn encode_bytes_nodejs(bytes: &[u8]) -> Value {
    encode_bytes_as_json(bytes, TYPE_BUFFER)
}

/// Base64 encode bytes to a string.
pub fn bytes_to_base64(bytes: &[u8]) -> String {
    general_purpose::STANDARD.encode(bytes)
}

/// Base64 decode a string to bytes.
pub fn base64_to_bytes(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD.decode(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_bytes_roundtrip() {
        let original = vec![1u8, 2, 3, 4, 5, 255, 0, 128];

        // Test Python-style encoding
        let encoded = encode_bytes_python(&original);
        if let Value::Object(obj) = &encoded {
            let decoded = try_decode_bytes_object(obj).expect("Should decode");
            assert_eq!(decoded, original);
        } else {
            panic!("Expected object");
        }

        // Test Node.js-style encoding
        let encoded_node = encode_bytes_nodejs(&original);
        if let Value::Object(obj) = &encoded_node {
            let decoded = try_decode_bytes_object(obj).expect("Should decode");
            assert_eq!(decoded, original);
        } else {
            panic!("Expected object");
        }
    }

    #[test]
    fn test_regular_object_not_decoded() {
        let mut obj = JsonMap::new();
        obj.insert("key".to_string(), Value::String("value".to_string()));

        assert!(try_decode_bytes_object(&obj).is_none());
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"Hello, World!";
        let encoded = bytes_to_base64(original);
        let decoded = base64_to_bytes(&encoded).expect("Should decode");
        assert_eq!(decoded, original);
    }
}
