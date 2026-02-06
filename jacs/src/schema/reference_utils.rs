use uuid::Uuid;

/// Validates that a string is a valid UUID.
pub fn validate_uuid_ref(id: &str) -> Result<(), String> {
    Uuid::parse_str(id)
        .map(|_| ())
        .map_err(|e| format!("Invalid UUID reference '{}': {}", id, e))
}

/// Builds a todo item reference in the format "list-uuid:item-uuid".
pub fn build_todo_item_ref(list_id: &str, item_id: &str) -> Result<String, String> {
    validate_uuid_ref(list_id).map_err(|e| format!("Invalid list ID: {}", e))?;
    validate_uuid_ref(item_id).map_err(|e| format!("Invalid item ID: {}", e))?;
    Ok(format!("{}:{}", list_id, item_id))
}

/// Parses a todo item reference "list-uuid:item-uuid" into (list_id, item_id).
pub fn parse_todo_item_ref(todo_ref: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = todo_ref.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid todo reference '{}': expected format 'list-uuid:item-uuid'",
            todo_ref
        ));
    }
    let list_id = parts[0];
    let item_id = parts[1];
    validate_uuid_ref(list_id)?;
    validate_uuid_ref(item_id)?;
    Ok((list_id.to_string(), item_id.to_string()))
}

/// Extracts a UUID reference field from a JSON document.
pub fn get_uuid_ref(doc: &serde_json::Value, field: &str) -> Option<String> {
    doc.get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_uuid_ref_valid() {
        let id = Uuid::new_v4().to_string();
        assert!(validate_uuid_ref(&id).is_ok());
    }

    #[test]
    fn test_validate_uuid_ref_invalid() {
        assert!(validate_uuid_ref("not-a-uuid").is_err());
        assert!(validate_uuid_ref("").is_err());
    }

    #[test]
    fn test_build_todo_item_ref() {
        let list_id = Uuid::new_v4().to_string();
        let item_id = Uuid::new_v4().to_string();
        let ref_str = build_todo_item_ref(&list_id, &item_id).unwrap();
        assert_eq!(ref_str, format!("{}:{}", list_id, item_id));
    }

    #[test]
    fn test_build_todo_item_ref_invalid_list() {
        let item_id = Uuid::new_v4().to_string();
        assert!(build_todo_item_ref("bad", &item_id).is_err());
    }

    #[test]
    fn test_build_todo_item_ref_invalid_item() {
        let list_id = Uuid::new_v4().to_string();
        assert!(build_todo_item_ref(&list_id, "bad").is_err());
    }

    #[test]
    fn test_parse_todo_item_ref() {
        let list_id = Uuid::new_v4().to_string();
        let item_id = Uuid::new_v4().to_string();
        let ref_str = format!("{}:{}", list_id, item_id);
        let (parsed_list, parsed_item) = parse_todo_item_ref(&ref_str).unwrap();
        assert_eq!(parsed_list, list_id);
        assert_eq!(parsed_item, item_id);
    }

    #[test]
    fn test_parse_todo_item_ref_no_colon() {
        assert!(parse_todo_item_ref("just-a-string").is_err());
    }

    #[test]
    fn test_parse_todo_item_ref_bad_uuids() {
        assert!(parse_todo_item_ref("bad:bad").is_err());
    }

    #[test]
    fn test_get_uuid_ref() {
        let doc = serde_json::json!({"myField": "abc-123"});
        assert_eq!(get_uuid_ref(&doc, "myField"), Some("abc-123".to_string()));
        assert_eq!(get_uuid_ref(&doc, "missing"), None);
    }
}
