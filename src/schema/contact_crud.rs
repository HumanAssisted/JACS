use serde_json::{json, Value};

use validator::ValidateEmail;

/// Creates a minimal contact with optional fields.
///
/// # Arguments
///
/// * `first_name` - The first name of the person.
/// * `last_name` - The last name of the person.
/// * `address_name` - The location name of the address.
/// * `phone` - The contact phone number.
/// * `email` - The contact email address.
/// * `mail_name` - The name to reach at the address.
/// * `mail_address` - The street and street address.
/// * `mail_address_two` - The second part of the mailing address.
/// * `mail_state` - The state or province.
/// * `mail_zip` - The zipcode.
/// * `mail_country` - The country.
/// * `is_primary` - Indicates if this is the primary way to contact the agent.
///
/// # Returns
///
/// A `serde_json::Value` representing the created contact.
///
/// # Errors
///
/// Returns an error if:
/// - `email` is provided but is not a valid email address.
pub fn create_minimal_contact(
    first_name: Option<&str>,
    last_name: Option<&str>,
    address_name: Option<&str>,
    phone: Option<&str>,
    email: Option<&str>,
    mail_name: Option<&str>,
    mail_address: Option<&str>,
    mail_address_two: Option<&str>,
    mail_state: Option<&str>,
    mail_zip: Option<&str>,
    mail_country: Option<&str>,
    is_primary: Option<bool>,
) -> Result<Value, String> {
    let mut contact = json!({});

    if let Some(first_name) = first_name {
        contact["firstName"] = json!(first_name);
    }
    if let Some(last_name) = last_name {
        contact["lastName"] = json!(last_name);
    }
    if let Some(address_name) = address_name {
        contact["addressName"] = json!(address_name);
    }
    if let Some(phone) = phone {
        contact["phone"] = json!(phone);
    }
    if let Some(email) = email {
        let email_valid: bool = ValidateEmail::validate_email(&email);
        if !email_valid {
            return Err(format!("Invalid email address: {}", email));
        }
        contact["email"] = json!(email);
    }
    if let Some(mail_name) = mail_name {
        contact["mailName"] = json!(mail_name);
    }
    if let Some(mail_address) = mail_address {
        contact["mailAddress"] = json!(mail_address);
    }
    if let Some(mail_address_two) = mail_address_two {
        contact["mailAddressTwo"] = json!(mail_address_two);
    }
    if let Some(mail_state) = mail_state {
        contact["mailState"] = json!(mail_state);
    }
    if let Some(mail_zip) = mail_zip {
        contact["mailZip"] = json!(mail_zip);
    }
    if let Some(mail_country) = mail_country {
        contact["mailCountry"] = json!(mail_country);
    }
    if let Some(is_primary) = is_primary {
        contact["isPrimary"] = json!(is_primary);
    }

    Ok(contact)
}
