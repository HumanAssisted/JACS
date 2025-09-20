use base64::{Engine as _, engine::general_purpose};
use libc::c_char;
use serde_json::{Map as JsonMap, Value};
use std::ffi::CString;
use std::ptr;

/// Convert a serde_json::Value to a C string
pub fn json_to_c_string(value: &Value) -> *mut c_char {
    match serde_json::to_string(value) {
        Ok(json_str) => match CString::new(json_str) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Convert a C string to a serde_json::Value
pub fn c_string_to_json(c_str: *const c_char) -> Result<Value, String> {
    if c_str.is_null() {
        return Err("Null pointer".to_string());
    }

    let json_str = unsafe {
        std::ffi::CStr::from_ptr(c_str)
            .to_str()
            .map_err(|e| e.to_string())?
    };

    serde_json::from_str(json_str).map_err(|e| e.to_string())
}

/// Encode binary data with type information for cross-language compatibility
pub fn encode_binary_data(data: &[u8]) -> Value {
    let base64_str = general_purpose::STANDARD.encode(data);
    
    let mut map = JsonMap::new();
    map.insert("__type__".to_string(), Value::String("bytes".to_string()));
    map.insert("data".to_string(), Value::String(base64_str));
    Value::Object(map)
}

/// Decode binary data from cross-language format
pub fn decode_binary_data(value: &Value) -> Option<Vec<u8>> {
    if let Value::Object(obj) = value {
        if let (Some(Value::String(type_str)), Some(Value::String(data))) =
            (obj.get("__type__"), obj.get("data"))
        {
            if type_str == "bytes" {
                return general_purpose::STANDARD.decode(data).ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_encode_decode_binary() {
        let data = b"Hello, World!";
        let encoded = encode_binary_data(data);
        
        assert!(encoded.is_object());
        assert_eq!(encoded["__type__"], "bytes");
        
        let decoded = decode_binary_data(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_json_conversion() {
        let value = json!({
            "name": "test",
            "count": 42,
            "active": true
        });

        let c_str = json_to_c_string(&value);
        assert!(!c_str.is_null());

        let converted = c_string_to_json(c_str).unwrap();
        assert_eq!(converted, value);

        // Clean up
        unsafe {
            let _ = CString::from_raw(c_str);
        }
    }
}
