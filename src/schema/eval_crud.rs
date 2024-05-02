use crate::agent::document::Document;
use crate::Agent;
use chrono::Utc;
use serde_json::{json, Value};
use std::error::Error;
use uuid::Uuid;

/// Creates an evaluation JSON object representing an agent's performance evaluation on a specific task.
///
/// This function constructs a signed and timestamped JSON object based on the given parameters. The created object complies with the specified evaluation schema and includes details such as the task's ID, qualitative descriptions, and optionally, quantitative assessments.
///
/// # Parameters
/// - `agent`: A mutable reference to an `Agent` object that will perform the signing of the evaluation.
/// - `qualityDescription`: A `serde_json::Value` containing descriptive text about the evaluation's context or qualitative aspects.
/// - `task_id`: A `String` representing the UUID of the task being evaluated.
/// - `units`: An optional vector of `serde_json::Value` objects representing quantitative evaluations, each conforming to the unit schema.
///
/// # Returns
/// Returns a `Result<Value, Box<dyn Error>>` where:
/// - `Ok(Value)`: A `serde_json::Value` representing the fully constructed and signed evaluation object if all operations are successful.
/// - `Err(Box<dyn Error>)`: An error boxed as a `dyn Error` that might occur during JSON manipulation, UUID generation, or the signing process.
///
/// # Examples
/// Basic usage:
///
/// ```rust
/// let mut agent = Agent::new(); // Assuming `Agent::new` is an appropriate constructor
/// let quality_description = json!("Quality of task execution was satisfactory.");
/// let task_id = Uuid::new_v4().to_string();
/// let units = Some(vec![json!({"unitName": "hours", "label": "work duration", "quantity": 5})]);
///
/// let evaluation = create_eval(&mut agent, quality_description, task_id, units).unwrap();
///
/// println!("Created Evaluation: {:?}", evaluation);
/// ```
///
/// # Errors
/// This function can return errors related to:
/// - JSON value construction, especially when inputs do not match expected formats.
/// - UUID generation for the evaluation ID.
/// - Digital signing errors within the `Agent`'s signing procedure.
///
pub fn create_eval (
    agent: &mut Agent,
    qualityDescription: Value,
    task_id: String,
    units: Option<Vec<Value>>,
) -> Result<Value, Box<dyn Error>> {
    let datetime = Utc::now();
    let schema =  "https://hai.ai/schemas/eval/v1/eval.schema.json" ;

    let mut eval = json!({
        "$schema": schema,
        "datetime": datetime.to_rfc3339(),
        "qualityDescription": qualityDescription,
        "taskID": task_id
    });

    // optionally add attachements
    if let Some(units_array) = units {
        eval["quantifications"] = Value::Array(units_array);
    }
    // sign
    eval["signature"] = agent.signing_procedure(&eval, None, &"signature".to_string())?;

    eval["id"] = json!(Uuid::new_v4().to_string());

    Ok(eval)
}


