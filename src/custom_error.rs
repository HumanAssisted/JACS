use std::error::Error;
use std::fmt;

/// A custom error type for handling errors within the JACS project.
#[derive(Debug)]
pub struct CustomError {
    message: String,
}

impl CustomError {
    /// Creates a new `CustomError` with the given message.
    pub fn new(message: &str) -> CustomError {
        CustomError {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for CustomError {}

impl From<&str> for CustomError {
    fn from(message: &str) -> Self {
        CustomError::new(message)
    }
}

impl From<String> for CustomError {
    fn from(message: String) -> Self {
        CustomError { message }
    }
}
