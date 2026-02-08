use serde_json::{Value, json};
use uuid::Uuid;

/// All valid commitment statuses.
const ALLOWED_STATUSES: &[&str] = &[
    "pending",
    "active",
    "completed",
    "failed",
    "renegotiated",
    "disputed",
    "revoked",
];

/// Creates a minimal commitment with just a description.
/// Status defaults to "pending".
pub fn create_minimal_commitment(description: &str) -> Result<Value, String> {
    if description.is_empty() {
        return Err("Commitment description cannot be empty".to_string());
    }

    let doc = json!({
        "$schema": "https://hai.ai/schemas/commitment/v1/commitment.schema.json",
        "jacsCommitmentDescription": description,
        "jacsCommitmentStatus": "pending",
        "id": Uuid::new_v4().to_string(),
        "jacsType": "commitment",
        "jacsLevel": "config",
    });

    Ok(doc)
}

/// Creates a commitment with structured terms.
pub fn create_commitment_with_terms(description: &str, terms: Value) -> Result<Value, String> {
    let mut doc = create_minimal_commitment(description)?;
    doc["jacsCommitmentTerms"] = terms;
    Ok(doc)
}

/// Updates the status of a commitment.
pub fn update_commitment_status(commitment: &mut Value, new_status: &str) -> Result<(), String> {
    if !ALLOWED_STATUSES.contains(&new_status) {
        return Err(format!(
            "Invalid commitment status: '{}'. Must be one of: {:?}",
            new_status, ALLOWED_STATUSES
        ));
    }
    commitment["jacsCommitmentStatus"] = json!(new_status);
    Ok(())
}

/// Sets the answer to the commitment question.
pub fn set_commitment_answer(commitment: &mut Value, answer: &str) -> Result<(), String> {
    commitment["jacsCommitmentAnswer"] = json!(answer);
    Ok(())
}

/// Sets the completion answer for the commitment.
pub fn set_commitment_completion_answer(
    commitment: &mut Value,
    answer: &str,
) -> Result<(), String> {
    commitment["jacsCommitmentCompletionAnswer"] = json!(answer);
    Ok(())
}

/// Updates the start and/or end dates of a commitment.
pub fn update_commitment_dates(
    commitment: &mut Value,
    start: Option<&str>,
    end: Option<&str>,
) -> Result<(), String> {
    if let Some(start_date) = start {
        commitment["jacsCommitmentStartDate"] = json!(start_date);
    }
    if let Some(end_date) = end {
        commitment["jacsCommitmentEndDate"] = json!(end_date);
    }
    Ok(())
}

/// Sets commitment status to "disputed" with a reason.
pub fn dispute_commitment(commitment: &mut Value, reason: &str) -> Result<(), String> {
    if reason.is_empty() {
        return Err("Dispute reason cannot be empty".to_string());
    }
    commitment["jacsCommitmentStatus"] = json!("disputed");
    commitment["jacsCommitmentDisputeReason"] = json!(reason);
    Ok(())
}

/// Sets commitment status to "revoked" with a reason.
pub fn revoke_commitment(commitment: &mut Value, reason: &str) -> Result<(), String> {
    if reason.is_empty() {
        return Err("Revocation reason cannot be empty".to_string());
    }
    commitment["jacsCommitmentStatus"] = json!("revoked");
    commitment["jacsCommitmentDisputeReason"] = json!(reason);
    Ok(())
}

/// Sets the conversation thread reference on a commitment.
pub fn set_conversation_ref(commitment: &mut Value, thread_id: &str) -> Result<(), String> {
    commitment["jacsCommitmentConversationRef"] = json!(thread_id);
    Ok(())
}

/// Sets the todo item reference on a commitment.
/// Format: "list-uuid:item-uuid"
pub fn set_todo_ref(commitment: &mut Value, todo_ref: &str) -> Result<(), String> {
    commitment["jacsCommitmentTodoRef"] = json!(todo_ref);
    Ok(())
}

/// Sets the task reference on a commitment.
pub fn set_task_ref(commitment: &mut Value, task_id: &str) -> Result<(), String> {
    commitment["jacsCommitmentTaskId"] = json!(task_id);
    Ok(())
}

/// Sets the question field on a commitment.
pub fn set_commitment_question(commitment: &mut Value, question: &str) -> Result<(), String> {
    commitment["jacsCommitmentQuestion"] = json!(question);
    Ok(())
}

/// Sets the completion question field on a commitment.
pub fn set_commitment_completion_question(
    commitment: &mut Value,
    question: &str,
) -> Result<(), String> {
    commitment["jacsCommitmentCompletionQuestion"] = json!(question);
    Ok(())
}

/// Sets the recurrence pattern on a commitment.
pub fn set_commitment_recurrence(
    commitment: &mut Value,
    frequency: &str,
    interval: u32,
) -> Result<(), String> {
    let allowed_frequencies = [
        "daily",
        "weekly",
        "biweekly",
        "monthly",
        "quarterly",
        "yearly",
    ];
    if !allowed_frequencies.contains(&frequency) {
        return Err(format!(
            "Invalid frequency: '{}'. Must be one of: {:?}",
            frequency, allowed_frequencies
        ));
    }
    if interval < 1 {
        return Err("Interval must be at least 1".to_string());
    }
    commitment["jacsCommitmentRecurrence"] = json!({
        "frequency": frequency,
        "interval": interval,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_minimal_commitment() {
        let doc = create_minimal_commitment("Deliver Q1 report").unwrap();
        assert_eq!(doc["jacsCommitmentDescription"], "Deliver Q1 report");
        assert_eq!(doc["jacsCommitmentStatus"], "pending");
        assert_eq!(doc["jacsType"], "commitment");
        assert_eq!(doc["jacsLevel"], "config");
    }

    #[test]
    fn test_create_minimal_commitment_empty_description() {
        let result = create_minimal_commitment("");
        assert!(result.is_err());
    }

    #[test]
    fn test_update_commitment_status_valid() {
        let mut doc = create_minimal_commitment("Test").unwrap();
        update_commitment_status(&mut doc, "active").unwrap();
        assert_eq!(doc["jacsCommitmentStatus"], "active");
    }

    #[test]
    fn test_update_commitment_status_invalid() {
        let mut doc = create_minimal_commitment("Test").unwrap();
        let result = update_commitment_status(&mut doc, "bogus");
        assert!(result.is_err());
    }

    #[test]
    fn test_dispute_commitment() {
        let mut doc = create_minimal_commitment("Test").unwrap();
        dispute_commitment(&mut doc, "Terms are unacceptable").unwrap();
        assert_eq!(doc["jacsCommitmentStatus"], "disputed");
        assert_eq!(doc["jacsCommitmentDisputeReason"], "Terms are unacceptable");
    }

    #[test]
    fn test_dispute_commitment_empty_reason() {
        let mut doc = create_minimal_commitment("Test").unwrap();
        let result = dispute_commitment(&mut doc, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_set_recurrence() {
        let mut doc = create_minimal_commitment("Weekly standup").unwrap();
        set_commitment_recurrence(&mut doc, "weekly", 1).unwrap();
        let recurrence = &doc["jacsCommitmentRecurrence"];
        assert_eq!(recurrence["frequency"], "weekly");
        assert_eq!(recurrence["interval"], 1);
    }

    #[test]
    fn test_set_recurrence_invalid_frequency() {
        let mut doc = create_minimal_commitment("Test").unwrap();
        let result = set_commitment_recurrence(&mut doc, "hourly", 1);
        assert!(result.is_err());
    }
}
