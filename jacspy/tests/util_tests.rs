// //tests here

// #![cfg(test)] // Only compile this module when running tests

// use pyo3::prelude::*;
// use serde_json::{json, Value};
// use std::ffi::CString;
// use pyo3::types::{
//     PyAny, PyBool, PyBytes, PyDateTime, PyDict, PyFloat, PyInt, PyList, PyNone, PyString,
// };

// // Assuming the functions are in the root of your lib crate (`crate::`)
// // If you put them in a module like `conversion_utils`, use:
// use jacspy::conversion_utils::{pyany_to_value, value_to_pyobject};

// #[test]
// fn test_pyany_to_value_conversion() {
//     Python::with_gil(|py| {
//         // --- Basic Types ---
//         assert_eq!(
//             pyany_to_value(py, py.None().bind(py)).unwrap(),
//             Value::Null
//         );
//         assert_eq!(
//             pyany_to_value(py, true.to_object(py).bind(py)).unwrap(),
//             Value::Bool(true)
//         );
//         assert_eq!(
//             pyany_to_value(py, false.to_object(py).bind(py)).unwrap(),
//             Value::Bool(false)
//         );
//         assert_eq!(
//             pyany_to_value(py, 123i64.to_object(py).bind(py)).unwrap(),
//             json!(123) // Use json! macro for numbers
//         );
//         assert_eq!(
//             pyany_to_value(py, (-456i64).to_object(py).bind(py)).unwrap(),
//             json!(-456)
//         );
//          // Test float - allow for minor precision differences if needed, but direct json! should work
//         assert_eq!(
//             pyany_to_value(py, 3.14f64.to_object(py).bind(py)).unwrap(),
//             json!(3.14)
//         );
//         assert_eq!(
//             pyany_to_value(py, "hello".to_object(py).bind(py)).unwrap(),
//             Value::String("hello".to_string())
//         );
//         assert_eq!(
//             pyany_to_value(py, "".to_object(py).bind(py)).unwrap(),
//             Value::String("".to_string())
//         );

//         // --- Lists ---
//         let pylist_empty = PyList::empty_bound(py);
//         assert_eq!(
//             pyany_to_value(py, &pylist_empty).unwrap(),
//             json!([])
//         );

//         let pylist_simple = PyList::new_bound(py, &[1.to_object(py), "two".to_object(py), true.to_object(py)]);
//         assert_eq!(
//             pyany_to_value(py, &pylist_simple).unwrap(),
//             json!([1, "two", true])
//         );

//         let nested_pylist = PyList::new_bound(py, &[pylist_simple.to_object(py)]);
//         assert_eq!(
//             pyany_to_value(py, &nested_pylist).unwrap(),
//             json!([[1, "two", true]])
//         );

//         // --- Dicts ---
//         let pydict_empty = PyDict::new_bound(py);
//         assert_eq!(
//             pyany_to_value(py, &pydict_empty).unwrap(),
//             json!({})
//         );

//         let pydict_simple = PyDict::new_bound(py);
//         pydict_simple.set_item("a", 1).unwrap();
//         pydict_simple.set_item("b", "bee").unwrap();
//         pydict_simple.set_item("c", py.None()).unwrap();
//         assert_eq!(
//             pyany_to_value(py, &pydict_simple).unwrap(),
//             json!({"a": 1, "b": "bee", "c": null})
//         );

//         let pydict_nested = PyDict::new_bound(py);
//         pydict_nested.set_item("nested", pydict_simple.to_object(py)).unwrap();
//         pydict_nested.set_item("list", pylist_simple.to_object(py)).unwrap();
//          assert_eq!(
//             pyany_to_value(py, &pydict_nested).unwrap(),
//             json!({
//                 "nested": {"a": 1, "b": "bee", "c": null},
//                 "list": [1, "two", true]
//             })
//         );

//         // --- Error Case ---
//         // Test unsupported type (e.g., a complex number)
//         // let globals = PyDict::new_bound(py);
//         // let locals = PyDict::new_bound(py);
//         // let code = CString::new("complex(1, 2)").unwrap();
//         // let complex_num = py.eval(&code, Some(&globals), Some(&locals)).unwrap();
//         // assert!(pyany_to_value(py, &complex_num).is_err());

//     });
// }

// #[test]
// fn test_value_to_pyobject_conversion() {
//     Python::with_gil(|py| {
//         // --- Basic Types ---
//         let py_none = value_to_pyobject(py, &Value::Null).unwrap();
//         assert!(py_none.bind(py).is_none());

//         let py_true = value_to_pyobject(py, &json!(true)).unwrap();
//         assert!(py_true.bind(py).downcast::<PyBool>().unwrap().is_true());

//         let py_false = value_to_pyobject(py, &json!(false)).unwrap();
//         assert!(!py_false.bind(py).downcast::<PyBool>().unwrap().is_true());

//         let py_int = value_to_pyobject(py, &json!(42)).unwrap();
//         assert_eq!(py_int.bind(py).extract::<i64>().unwrap(), 42);

//          let py_neg_int = value_to_pyobject(py, &json!(-10)).unwrap();
//         assert_eq!(py_neg_int.bind(py).extract::<i64>().unwrap(), -10);

//         let py_float = value_to_pyobject(py, &json!(9.81)).unwrap();
//         assert!((py_float.bind(py).extract::<f64>().unwrap() - 9.81).abs() < f64::EPSILON);

//         let py_string = value_to_pyobject(py, &json!("world")).unwrap();
//         assert_eq!(py_string.bind(py).extract::<String>().unwrap(), "world");

//         let py_empty_string = value_to_pyobject(py, &json!("")).unwrap();
//         assert_eq!(py_empty_string.bind(py).extract::<String>().unwrap(), "");

//         // --- Lists ---
//         let py_list_empty = value_to_pyobject(py, &json!([])).unwrap();
//         assert!(py_list_empty.bind(py).downcast::<PyList>().unwrap().is_empty());

//         let py_list_simple = value_to_pyobject(py, &json!([false, 5, "x"])).unwrap();
//         let bound_list = py_list_simple.bind(py).downcast::<PyList>().unwrap();
//         assert_eq!(bound_list.len(), 3);
//         assert!(!bound_list.get_item(0).unwrap().extract::<bool>().unwrap());
//         assert_eq!(bound_list.get_item(1).unwrap().extract::<i64>().unwrap(), 5);
//         assert_eq!(bound_list.get_item(2).unwrap().extract::<String>().unwrap(), "x");

//         let py_list_nested = value_to_pyobject(py, &json!([[1, 2], []])).unwrap();
//         let bound_nested_list = py_list_nested.bind(py).downcast::<PyList>().unwrap();
//         assert_eq!(bound_nested_list.len(), 2);
//         assert!(bound_nested_list.get_item(0).unwrap().is_instance_of::<PyList>());
//         assert!(bound_nested_list.get_item(1).unwrap().downcast::<PyList>().unwrap().is_empty());

//         // --- Objects ---
//         let py_obj_empty = value_to_pyobject(py, &json!({})).unwrap();
//         assert!(py_obj_empty.bind(py).downcast::<PyDict>().unwrap().is_empty());

//         let py_obj_simple = value_to_pyobject(py, &json!({"x": 10, "y": null, "z": "zee"})).unwrap();
//         let bound_dict = py_obj_simple.bind(py).downcast::<PyDict>().unwrap();
//         assert_eq!(bound_dict.len(), 3);
//         assert_eq!(bound_dict.get_item("x").unwrap().unwrap().extract::<i64>().unwrap(), 10);
//         assert!(bound_dict.get_item("y").unwrap().unwrap().is_none());
//         assert_eq!(bound_dict.get_item("z").unwrap().unwrap().extract::<String>().unwrap(), "zee");

//         let py_obj_nested = value_to_pyobject(py, &json!({"data": [1], "nested": {"a": true}})).unwrap();
//         let bound_nested_dict = py_obj_nested.bind(py).downcast::<PyDict>().unwrap();
//         assert_eq!(bound_nested_dict.len(), 2);
//         assert!(bound_nested_dict.get_item("data").unwrap().unwrap().is_instance_of::<PyList>());
//         assert!(bound_nested_dict.get_item("nested").unwrap().unwrap().is_instance_of::<PyDict>());
//     });
// }
