use serde_json::{json, Value};
use validator::Validate;

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
fn create_minimal_contact(
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
        let email_value = validator::validate_email(email);
        if let Err(e) = email_value {
            return Err(format!("Invalid email address: {}", e));
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

/// Updates the first name of a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
/// * `new_first_name` - The new first name for the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact first name was updated successfully.
/// * `Err(String)` - If an error occurred while updating the contact first name.
fn update_contact_first_name(contact: &mut Value, new_first_name: &str) -> Result<(), String> {
    contact["firstName"] = json!(new_first_name);
    Ok(())
}

/// Updates the last name of a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
/// * `new_last_name` - The new last name for the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact last name was updated successfully.
/// * `Err(String)` - If an error occurred while updating the contact last name.
fn update_contact_last_name(contact: &mut Value, new_last_name: &str) -> Result<(), String> {
    contact["lastName"] = json!(new_last_name);
    Ok(())
}

/// Updates the email of a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
/// * `new_email` - The new email for the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact email was updated successfully.
/// * `Err(String)` - If an error occurred while updating the contact email.
fn update_contact_email(contact: &mut Value, new_email: &str) -> Result<(), String> {
    let email_value = validator::validate_email(new_email);
    if let Err(e) = email_value {
        return Err(format!("Invalid email address: {}", e));
    }
    contact["email"] = json!(new_email);
    Ok(())
}

/// Removes the email from a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact email was removed successfully.
/// * `Err(String)` - If an error occurred while removing the contact email.
fn remove_contact_email(contact: &mut Value) -> Result<(), String> {
    contact
        .as_object_mut()
        .ok_or_else(|| "Invalid contact format".to_string())?
        .remove("email");
    Ok(())
}

/// Updates the phone of a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
/// * `new_phone` - The new phone for the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact phone was updated successfully.
/// * `Err(String)` - If an error occurred while updating the contact phone.
fn update_contact_phone(contact: &mut Value, new_phone: &str) -> Result<(), String> {
    contact["phone"] = json!(new_phone);
    Ok(())
}

/// Removes the phone from a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact phone was removed successfully.
/// * `Err(String)` - If an error occurred while removing the contact phone.
fn remove_contact_phone(contact: &mut Value) -> Result<(), String> {
    contact
        .as_object_mut()
        .ok_or_else(|| "Invalid contact format".to_string())?
        .remove("phone");
    Ok(())
}

/// Updates the address name of a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
/// * `new_address_name` - The new address name for the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact address name was updated successfully.
/// * `Err(String)` - If an error occurred while updating the contact address name.
fn update_contact_address_name(contact: &mut Value, new_address_name: &str) -> Result<(), String> {
    contact["addressName"] = json!(new_address_name);
    Ok(())
}

/// Removes the address name from a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact address name was removed successfully.
/// * `Err(String)` - If an error occurred while removing the contact address name.
fn remove_contact_address_name(contact: &mut Value) -> Result<(), String> {
    contact
        .as_object_mut()
        .ok_or_else(|| "Invalid contact format".to_string())?
        .remove("addressName");
    Ok(())
}

/// Updates the mail address of a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
/// * `new_mail_address` - The new mail address for the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact mail address was updated successfully.
/// * `Err(String)` - If an error occurred while updating the contact mail address.
fn update_contact_mail_address(contact: &mut Value, new_mail_address: &str) -> Result<(), String> {
    contact["mailAddress"] = json!(new_mail_address);
    Ok(())
}

/// Removes the mail address from a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact mail address was removed successfully.
/// * `Err(String)` - If an error occurred while removing the contact mail address.
fn remove_contact_mail_address(contact: &mut Value) -> Result<(), String> {
    contact
        .as_object_mut()
        .ok_or_else(|| "Invalid contact format".to_string())?
        .remove("mailAddress");
    Ok(())
}

/// Updates the mail address two of a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
/// * `new_mail_address_two` - The new mail address two for the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact mail address two was updated successfully.
/// * `Err(String)` - If an error occurred while updating the contact mail address two.
fn update_contact_mail_address_two(contact: &mut Value, new_mail_address_two: &str) -> Result<(), String> {
    contact["mailAddressTwo"] = json!(new_mail_address_two);
    Ok(())
}

/// Removes the mail address two from a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact mail address two was removed successfully.
/// * `Err(String)` - If an error occurred while removing the contact mail address two.
fn remove_contact_mail_address_two(contact: &mut Value) -> Result<(), String> {
    contact
        .as_object_mut()
        .ok_or_else(|| "Invalid contact format".to_string())?
        .remove("mailAddressTwo");
    Ok(())
}

/// Updates the mail state of a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
/// * `new_mail_state` - The new mail state for the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact mail state was updated successfully.
/// * `Err(String)` - If an error occurred while updating the contact mail state.
fn update_contact_mail_state(contact: &mut Value, new_mail_state: &str) -> Result<(), String> {
    contact["mailState"] = json!(new_mail_state);
    Ok(())
}

/// Removes the mail state from a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact mail state was removed successfully.
/// * `Err(String)` - If an error occurred while removing the contact mail state.
fn remove_contact_mail_state(contact: &mut Value) -> Result<(), String> {
    contact
        .as_object_mut()
        .ok_or_else(|| "Invalid contact format".to_string())?
        .remove("mailState");
    Ok(())
}

/// Updates the mail zip of a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
/// * `new_mail_zip` - The new mail zip for the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact mail zip was updated successfully.
/// * `Err(String)` - If an error occurred while updating the contact mail zip.
fn update_contact_mail_zip(contact: &mut Value, new_mail_zip: &str) -> Result<(), String> {
    contact["mailZip"] = json!(new_mail_zip);
    Ok(())
}

/// Removes the mail zip from a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact mail zip was removed successfully.
/// * `Err(String)` - If an error occurred while removing the contact mail zip.
fn remove_contact_mail_zip(contact: &mut Value) -> Result<(), String> {
    contact
        .as_object_mut()
        .ok_or_else(|| "Invalid contact format".to_string())?
        .remove("mailZip");
    Ok(())
}

/// Updates the mail country of a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
/// * `new_mail_country` - The new mail country for the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact mail country was updated successfully.
/// * `Err(String)` - If an error occurred while updating the contact mail country.
fn update_contact_mail_country(contact: &mut Value, new_mail_country: &str) -> Result<(), String> {
    contact["mailCountry"] = json!(new_mail_country);
    Ok(())
}

/// Removes the mail country from a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact mail country was removed successfully.
/// * `Err(String)` - If an error occurred while removing the contact mail country.
fn remove_contact_mail_country(contact: &mut Value) -> Result<(), String> {
    contact
        .as_object_mut()
        .ok_or_else(|| "Invalid contact format".to_string())?
        .remove("mailCountry");
    Ok(())
}

/// Updates the primary status of a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
/// * `is_primary` - The new primary status for the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact primary status was updated successfully.
/// * `Err(String)` - If an error occurred while updating the contact primary status.
fn update_contact_is_primary(contact: &mut Value, is_primary: bool) -> Result<(), String> {
    contact["isPrimary"] = json!(is_primary);
    Ok(())
}

/// Removes the primary status from a contact.
///
/// # Arguments
///
/// * `contact` - A mutable reference to the contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact primary status was removed successfully.
/// * `Err(String)` - If an error occurred while removing the contact primary status.
fn remove_contact_is_primary(contact: &mut Value) -> Result<(), String> {
    contact
        .as_object_mut()
        .ok_or_else(|| "Invalid contact format".to_string())?
        .remove("isPrimary");
    Ok(())
}