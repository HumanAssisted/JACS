use pyo3::prelude::*;
use jacs::python::jacs_agent::JacsAgent;

#[pymodule]
fn jacs(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<JacsAgent>()?;
    Ok(())
}