use serde_json::{json, Value};

/// Creates a minimal service with required fields and optional tools and PII desired.
///
/// # Arguments
///
/// * `service_description` - The description of the service.
/// * `success_description` - The description of successful delivery of the service.
/// * `failure_description` - The description of failure of delivery of the service.
/// * `tools` - An optional vector of tools associated with the service.
/// * `pii_desired` - An optional vector of desired personally identifiable information (PII).
///
/// # Returns
///
/// A `serde_json::Value` representing the created service.
///
/// # Errors
///
/// Returns an error if:
/// - `service_description`, `success_description`, or `failure_description` is empty.
pub fn create_minimal_service(
    service_description: &str,
    success_description: &str,
    failure_description: &str,
    tools: Option<Vec<Value>>,
    pii_desired: Option<Vec<String>>,
) -> Result<Value, String> {
    if service_description.is_empty() {
        return Err("Service description cannot be empty".to_string());
    }
    if success_description.is_empty() {
        return Err("Success description cannot be empty".to_string());
    }
    if failure_description.is_empty() {
        return Err("Failure description cannot be empty".to_string());
    }

    let mut service = json!({
        "serviceDescription": service_description,
        "successDescription": success_description,
        "failureDescription": failure_description,
    });

    if let Some(tools) = tools {
        service["tools"] = json!(tools);
    }

    if let Some(pii_desired) = pii_desired {
        service["piiDesired"] = json!(pii_desired);
    }

    Ok(service)
}

// Functions removed due to being unused, addressing compiler warnings for dead code.
