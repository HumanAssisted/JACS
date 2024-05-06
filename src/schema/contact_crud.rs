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

// Removed unused function update_contact_email
// Removed unused function remove_contact_email

#[allow(dead_code)]
fn update_contact_address_name(contact: &mut Value, new_address_name: &str) -> Result<(), String> {
    contact["addressName"] = json!(new_address_name);
    Ok(())
}

#[allow(dead_code)]
fn remove_contact_address_name(contact: &mut Value) -> Result<(), String> {
    contact
        .as_object_mut()
        .ok_or_else(|| "Invalid contact format".to_string())?
        .remove("addressName");
    Ok(())
}

// fn update_contact_mail_address(contact: &mut Value, new_mail_address: &str) -> Result<(), String> {
//     contact["mailAddress"] = json!(new_mail_address);
//     Ok(())
// }

// fn remove_contact_mail_address(contact: &mut Value) -> Result<(), String> {
//     contact
//         .as_object_mut()
//         .ok_or_else(|| "Invalid contact format".to_string())?
//         .remove("mailAddress");
//     Ok(())
// }

// fn update_contact_mail_address_two(
//     contact: &mut Value,
//     new_mail_address_two: &str,
// ) -> Result<(), String> {
//     contact["mailAddressTwo"] = json!(new_mail_address_two);
//     Ok(())
// }

// fn remove_contact_mail_address_two(contact: &mut Value) -> Result<(), String> {
//     contact
//         .as_object_mut()
//         .ok_or_else(|| "Invalid contact format".to_string())?
//         .remove("mailAddressTwo");
//     Ok(())
// }

#[allow(dead_code)]
fn update_contact_mail_state(contact: &mut Value, new_mail_state: &str) -> Result<(), String> {
    contact["mailState"] = json!(new_mail_state);
    Ok(())
}

#[allow(dead_code)]
fn remove_contact_mail_state(contact: &mut Value) -> Result<(), String> {
    contact
        .as_object_mut()
        .ok_or_else(|| "Invalid contact format".to_string())?
        .remove("mailState");
    Ok(())
}

// fn update_contact_mail_zip(contact: &mut Value, new_mail_zip: &str) -> Result<(), String> {
//     contact["mailZip"] = json!(new_mail_zip);
//     Ok(())
// }

// fn remove_contact_mail_zip(contact: &mut Value) -> Result<(), String> {
//     contact
//         .as_object_mut()
//         .ok_or_else(|| "Invalid contact format".to_string())?
//         .remove("mailZip");
//     Ok(())
// }

#[allow(dead_code)]
fn update_contact_mail_country(contact: &mut Value, new_mail_country: &str) -> Result<(), String> {
    contact["mailCountry"] = json!(new_mail_country);
    Ok(())
}

#[allow(dead_code)]
fn remove_contact_mail_country(contact: &mut Value) -> Result<(), String> {
    contact
        .as_object_mut()
        .ok_or_else(|| "Invalid contact format".to_string())?
        .remove("mailCountry");
    Ok(())
}
