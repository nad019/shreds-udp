use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("corruption: {0}")]
    Corruption(String),
}
