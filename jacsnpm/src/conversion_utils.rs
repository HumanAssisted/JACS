use base64::{Engine as _, engine::general_purpose};
use napi::bindgen_prelude::*;
use serde_json::{Map as JsonMap, Value};

/// Converts a JavaScript value into a serde_json::Value.
pub fn js_value_to_value(env: Env, value: JsUnknown) -> Result<Value> {
    if value.is_null()? || value.is_undefined()? {
        return Ok(Value::Null);
    }

    if value.is_boolean()? {
        let bool_val = value.coerce_to_bool()?.get_value()?;
        return Ok(Value::Bool(bool_val));
    }

    if value.is_number()? {
        let num_val = value.coerce_to_number()?.get_double()?;
        return Ok(Value::Number(serde_json::Number::from_f64(num_val).ok_or_else(
            || Error::new(Status::InvalidArg, "Invalid number value"),
        )?));
    }

    if value.is_string()? {
        let string_val = value.coerce_to_string()?.into_utf8()?.into_owned()?;
        return Ok(Value::String(string_val));
    }

    if value.is_buffer()? {
        let buffer: JsBuffer = unsafe { value.cast() };
        let bytes_data = buffer.into_value()?;
        let base64_str = general_purpose::STANDARD.encode(&bytes_data);

        // Create a JSON object with type information and data
        let mut map = JsonMap::new();
        map.insert("__type__".to_string(), Value::String("buffer".to_string()));
        map.insert("data".to_string(), Value::String(base64_str));
        return Ok(Value::Object(map));
    }

    if value.is_array()? {
        let array: JsObject = unsafe { value.cast() };
        let length = array.get_array_length()?;
        let mut vec = Vec::with_capacity(length as usize);

        for i in 0..length {
            let item = array.get_element::<JsUnknown>(i)?;
            vec.push(js_value_to_value(env, item)?);
        }
        return Ok(Value::Array(vec));
    }

    if value.is_object()? {
        let obj: JsObject = unsafe { value.cast() };
        let properties = obj.get_property_names()?;
        let length = properties.get_array_length()?;
        let mut map = JsonMap::new();

        for i in 0..length {
            let key = properties.get_element::<JsString>(i)?;
            let key_str = key.into_utf8()?.into_owned()?;
            let value_obj = obj.get_property::<JsUnknown>(&key_str)?;
            map.insert(key_str, js_value_to_value(env, value_obj)?);
        }
        return Ok(Value::Object(map));
    }

    Err(Error::new(
        Status::InvalidArg,
        format!("Unsupported JavaScript type for JSON conversion"),
    ))
}

/// Converts a serde_json::Value to a JavaScript value.
pub fn value_to_js_value(env: Env, value: &Value) -> Result<JsUnknown> {
    match value {
        Value::Null => Ok(env.get_null()?.into_unknown()),
        Value::Bool(b) => Ok(env.get_boolean(*b)?.into_unknown()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(env.create_int64(i)?.into_unknown())
            } else if let Some(u) = n.as_u64() {
                if u <= i64::MAX as u64 {
                    Ok(env.create_int64(u as i64)?.into_unknown())
                } else {
                    Ok(env.create_double(u as f64)?.into_unknown())
                }
            } else if let Some(f) = n.as_f64() {
                Ok(env.create_double(f)?.into_unknown())
            } else {
                Err(Error::new(
                    Status::InvalidArg,
                    "Invalid JSON number",
                ))
            }
        }
        Value::String(s) => Ok(env.create_string(s)?.into_unknown()),
        Value::Array(a) => {
            let array = env.create_array(a.len() as u32)?;
            for (i, item) in a.iter().enumerate() {
                let js_item = value_to_js_value(env, item)?;
                array.set_element(i as u32, js_item)?;
            }
            Ok(array.into_unknown())
        }
        Value::Object(o) => {
            // Check if this is a specially encoded type
            if let (Some(Value::String(type_str)), Some(Value::String(data))) =
                (o.get("__type__"), o.get("data"))
            {
                match type_str.as_str() {
                    "buffer" => {
                        // Decode base64 string back to bytes
                        let bytes = general_purpose::STANDARD.decode(data).map_err(|e| {
                            Error::new(
                                Status::InvalidArg,
                                format!("Failed to decode base64 string: {}", e),
                            )
                        })?;
                        let buffer = env.create_buffer_with_data(bytes)?;
                        Ok(buffer.into_unknown())
                    }
                    _ => {
                        // If it's not a recognized special type, treat as normal object
                        let obj = env.create_object()?;
                        for (key, val) in o {
                            let js_val = value_to_js_value(env, val)?;
                            obj.set_named_property(key, js_val)?;
                        }
                        Ok(obj.into_unknown())
                    }
                }
            } else {
                // Regular object
                let obj = env.create_object()?;
                for (key, val) in o {
                    let js_val = value_to_js_value(env, val)?;
                    obj.set_named_property(key, js_val)?;
                }
                Ok(obj.into_unknown())
            }
        }
    }
} 