use base64::{Engine as _, engine::general_purpose};
use pyo3::IntoPyObjectExt;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyBytes, PyDict, PyList, PyString};
use serde_json::{Map as JsonMap, Value};

/// Converts a Bound<'_, PyAny> into a serde_json::Value.
pub fn pyany_to_value(py: Python, obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    if obj.is_none() {
        Ok(Value::Null)
    } else if let Ok(b) = obj.downcast::<PyBool>() {
        Ok(Value::Bool(b.is_true()))
    } else if let Ok(i) = obj.extract::<i64>() {
        Ok(Value::Number(i.into()))
    } else if let Ok(f) = obj.extract::<f64>() {
        Ok(Value::Number(serde_json::Number::from_f64(f).ok_or_else(
            || PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid float value"),
        )?))
    } else if let Ok(s) = obj.downcast::<PyString>() {
        Ok(Value::String(s.to_string_lossy().into_owned()))
    } else if let Ok(bytes) = obj.downcast::<PyBytes>() {
        // Convert bytes to base64 encoded string with a type marker
        let bytes_data = bytes.as_bytes();
        let base64_str = general_purpose::STANDARD.encode(bytes_data);

        // Create a JSON object with type information and data
        let mut map = JsonMap::new();
        map.insert("__type__".to_string(), Value::String("bytes".to_string()));
        map.insert("data".to_string(), Value::String(base64_str));
        Ok(Value::Object(map))
    }
    // else if let Ok(_datetime) = obj.downcast::<PyDateTime>() {
    //     // Extract datetime as ISO format string
    //     let datetime_str = obj.call_method0("isoformat")?.extract::<String>()?;

    //     // Create a JSON object with type information and data
    //     let mut map = JsonMap::new();
    //     map.insert("__type__".to_string(), Value::String("datetime".to_string()));
    //     map.insert("data".to_string(), Value::String(datetime_str));
    //     Ok(Value::Object(map))
    // }
    else if let Ok(list) = obj.downcast::<PyList>() {
        let mut vec = Vec::new();
        for item_obj in list.iter() {
            vec.push(pyany_to_value(py, &item_obj)?);
        }
        Ok(Value::Array(vec))
    } else if let Ok(dict) = obj.downcast::<PyDict>() {
        let mut map = JsonMap::new();
        for (key_obj, value_obj) in dict.iter() {
            let key = key_obj.extract::<String>()?;
            map.insert(key, pyany_to_value(py, &value_obj)?);
        }
        Ok(Value::Object(map))
    } else {
        let type_name = obj.get_type().qualname()?;
        Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(format!(
            "Unsupported Python type for JSON conversion: {}",
            type_name
        )))
    }
}

// Helper function to convert serde_json::Value to PyObject
pub fn value_to_pyobject(py: Python, value: &Value) -> PyResult<PyObject> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => (*b).into_py_any(py),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_py_any(py)
            } else if let Some(u) = n.as_u64() {
                u.into_py_any(py)
            } else if let Some(f) = n.as_f64() {
                f.into_py_any(py)
            } else {
                Err(pyo3::exceptions::PyValueError::new_err(
                    "Invalid JSON number",
                ))
            }
        }
        Value::String(s) => s.clone().into_py_any(py),
        Value::Array(a) => {
            let mut py_items = Vec::with_capacity(a.len());
            for item in a {
                py_items.push(value_to_pyobject(py, item)?);
            }
            let list = PyList::new(py, py_items)?;
            Ok(list.into_any().unbind())
        }
        Value::Object(o) => {
            // Check if this is a specially encoded type
            if let (Some(Value::String(type_str)), Some(Value::String(data))) =
                (o.get("__type__"), o.get("data"))
            {
                match type_str.as_str() {
                    "bytes" => {
                        // Decode base64 string back to bytes
                        let bytes = general_purpose::STANDARD.decode(data).map_err(|e| {
                            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                                "Failed to decode base64 string: {}",
                                e
                            ))
                        })?;
                        Ok(PyBytes::new(py, &bytes).into_any().unbind())
                    }
                    // "datetime" => {
                    //     // Import datetime module and create a datetime object
                    //     let datetime = py.import("datetime")?;
                    //     let args = PyTuple::new_bound(py, &[]);
                    //     let kwargs = PyDict::new_bound(py);
                    //     kwargs.set_item("fromisoformat", datetime.getattr("datetime")?.getattr("fromisoformat")?)?;
                    //     kwargs.set_item("iso_string", data)?;

                    //     // Call datetime.datetime.fromisoformat(iso_string)
                    //     let fromisoformat = datetime.getattr("datetime")?.getattr("fromisoformat")?;
                    //     let dt = fromisoformat.call1((data,))?;
                    //     Ok(dt.into_py(py))
                    // },
                    _ => {
                        // If it's not a recognized special type, treat as normal dict
                        let dict = PyDict::new(py);
                        for (key, val) in o {
                            dict.set_item(key, value_to_pyobject(py, val)?)?;
                        }
                        Ok(dict.into_any().unbind())
                    }
                }
            } else {
                // Regular dictionary
                let dict = PyDict::new(py);
                for (key, val) in o {
                    dict.set_item(key, value_to_pyobject(py, val)?)?;
                }
                Ok(dict.into_any().unbind())
            }
        }
    }
}

// --- Unit Tests ---
#[cfg(test)] // Only compile this module when running tests
mod tests {
    use super::*; // Import items from the parent module (conversion_utils)
    use pyo3::prelude::*;
    use pyo3::types::{PyBool, PyDict, PyList}; // Keep necessary type imports
    use serde_json::{Value, json};
    // use std::ffi::CString; // No longer needed for complex number test here if removed

    #[test]
    fn test_pyany_to_value_conversion() {
        Python::with_gil(|py| {
            // --- Basic Types ---
            assert_eq!(pyany_to_value(py, py.None().bind(py)).unwrap(), Value::Null);
            assert_eq!(
                pyany_to_value(py, true.to_object(py).bind(py)).unwrap(),
                Value::Bool(true)
            );
            assert_eq!(
                pyany_to_value(py, false.to_object(py).bind(py)).unwrap(),
                Value::Bool(false)
            );
            assert_eq!(
                pyany_to_value(py, 123i64.to_object(py).bind(py)).unwrap(),
                json!(123) // Use json! macro for numbers
            );
            assert_eq!(
                pyany_to_value(py, (-456i64).to_object(py).bind(py)).unwrap(),
                json!(-456)
            );
            assert_eq!(
                pyany_to_value(py, 3.14f64.to_object(py).bind(py)).unwrap(),
                json!(3.14)
            );
            assert_eq!(
                pyany_to_value(py, "hello".to_object(py).bind(py)).unwrap(),
                Value::String("hello".to_string())
            );
            assert_eq!(
                pyany_to_value(py, "".to_object(py).bind(py)).unwrap(),
                Value::String("".to_string())
            );

            // --- Lists ---
            let pylist_empty = PyList::empty_bound(py);
            assert_eq!(pyany_to_value(py, &pylist_empty).unwrap(), json!([]));

            let pylist_simple = PyList::new_bound(
                py,
                &[1.to_object(py), "two".to_object(py), true.to_object(py)],
            );
            assert_eq!(
                pyany_to_value(py, &pylist_simple).unwrap(),
                json!([1, "two", true])
            );

            let nested_pylist = PyList::new_bound(py, &[pylist_simple.to_object(py)]);
            assert_eq!(
                pyany_to_value(py, &nested_pylist).unwrap(),
                json!([[1, "two", true]])
            );

            // --- Dicts ---
            let pydict_empty = PyDict::new_bound(py);
            assert_eq!(pyany_to_value(py, &pydict_empty).unwrap(), json!({}));

            let pydict_simple = PyDict::new_bound(py);
            pydict_simple.set_item("a", 1).unwrap();
            pydict_simple.set_item("b", "bee").unwrap();
            pydict_simple.set_item("c", py.None()).unwrap();
            assert_eq!(
                pyany_to_value(py, &pydict_simple).unwrap(),
                json!({"a": 1, "b": "bee", "c": null})
            );

            let pydict_nested = PyDict::new_bound(py);
            pydict_nested
                .set_item("nested", pydict_simple.to_object(py))
                .unwrap();
            pydict_nested
                .set_item("list", pylist_simple.to_object(py))
                .unwrap();
            assert_eq!(
                pyany_to_value(py, &pydict_nested).unwrap(),
                json!({
                    "nested": {"a": 1, "b": "bee", "c": null},
                    "list": [1, "two", true]
                })
            );

            // --- Error Case ---
            // Example: Test unsupported type (e.g., a set)
            // let set_obj = py.eval("{1, 2, 3}", None, None).unwrap();
            // assert!(pyany_to_value(py, &set_obj).is_err());
        });
    }

    #[test]
    fn test_value_to_pyobject_conversion() {
        Python::with_gil(|py| {
            // --- Basic Types ---
            let py_none = value_to_pyobject(py, &Value::Null).unwrap();
            assert!(py_none.bind(py).is_none());

            let py_true = value_to_pyobject(py, &json!(true)).unwrap();
            assert!(py_true.bind(py).downcast::<PyBool>().unwrap().is_true());

            let py_false = value_to_pyobject(py, &json!(false)).unwrap();
            assert!(!py_false.bind(py).downcast::<PyBool>().unwrap().is_true());

            let py_int = value_to_pyobject(py, &json!(42)).unwrap();
            assert_eq!(py_int.bind(py).extract::<i64>().unwrap(), 42);

            let py_neg_int = value_to_pyobject(py, &json!(-10)).unwrap();
            assert_eq!(py_neg_int.bind(py).extract::<i64>().unwrap(), -10);

            let py_float = value_to_pyobject(py, &json!(9.81)).unwrap();
            assert!((py_float.bind(py).extract::<f64>().unwrap() - 9.81).abs() < f64::EPSILON);

            let py_string = value_to_pyobject(py, &json!("world")).unwrap();
            assert_eq!(py_string.bind(py).extract::<String>().unwrap(), "world");

            let py_empty_string = value_to_pyobject(py, &json!("")).unwrap();
            assert_eq!(py_empty_string.bind(py).extract::<String>().unwrap(), "");

            // --- Lists ---
            let py_list_empty = value_to_pyobject(py, &json!([])).unwrap();
            assert!(
                py_list_empty
                    .bind(py)
                    .downcast::<PyList>()
                    .unwrap()
                    .is_empty()
            );

            let py_list_simple = value_to_pyobject(py, &json!([false, 5, "x"])).unwrap();
            let bound_list = py_list_simple.bind(py).downcast::<PyList>().unwrap();
            assert_eq!(bound_list.len(), 3);
            assert!(!bound_list.get_item(0).unwrap().extract::<bool>().unwrap());
            assert_eq!(bound_list.get_item(1).unwrap().extract::<i64>().unwrap(), 5);
            assert_eq!(
                bound_list.get_item(2).unwrap().extract::<String>().unwrap(),
                "x"
            );

            let py_list_nested = value_to_pyobject(py, &json!([[1, 2], []])).unwrap();
            let bound_nested_list = py_list_nested.bind(py).downcast::<PyList>().unwrap();
            assert_eq!(bound_nested_list.len(), 2);
            assert!(
                bound_nested_list
                    .get_item(0)
                    .unwrap()
                    .is_instance_of::<PyList>()
            );
            assert!(
                bound_nested_list
                    .get_item(1)
                    .unwrap()
                    .downcast::<PyList>()
                    .unwrap()
                    .is_empty()
            );

            // --- Objects ---
            let py_obj_empty = value_to_pyobject(py, &json!({})).unwrap();
            assert!(
                py_obj_empty
                    .bind(py)
                    .downcast::<PyDict>()
                    .unwrap()
                    .is_empty()
            );

            let py_obj_simple =
                value_to_pyobject(py, &json!({"x": 10, "y": null, "z": "zee"})).unwrap();
            let bound_dict = py_obj_simple.bind(py).downcast::<PyDict>().unwrap();
            assert_eq!(bound_dict.len(), 3);
            assert_eq!(
                bound_dict
                    .get_item("x")
                    .unwrap()
                    .unwrap()
                    .extract::<i64>()
                    .unwrap(),
                10
            );
            assert!(bound_dict.get_item("y").unwrap().unwrap().is_none());
            assert_eq!(
                bound_dict
                    .get_item("z")
                    .unwrap()
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "zee"
            );

            let py_obj_nested =
                value_to_pyobject(py, &json!({"data": [1], "nested": {"a": true}})).unwrap();
            let bound_nested_dict = py_obj_nested.bind(py).downcast::<PyDict>().unwrap();
            assert_eq!(bound_nested_dict.len(), 2);
            assert!(
                bound_nested_dict
                    .get_item("data")
                    .unwrap()
                    .unwrap()
                    .is_instance_of::<PyList>()
            );
            assert!(
                bound_nested_dict
                    .get_item("nested")
                    .unwrap()
                    .unwrap()
                    .is_instance_of::<PyDict>()
            );
        });
    }
}

// #[pymodule]
// fn jacs(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
//     pyo3::types::PyDateTime::init_type();
//     // rest of your code...
//     Ok(())
// }
