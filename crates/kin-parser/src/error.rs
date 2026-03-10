use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("unsupported language: {0}")]
    UnsupportedLanguage(String),

    #[error("tree-sitter parse failed for {file}: {reason}")]
    ParseFailed { file: String, reason: String },

    #[error("tree-sitter language load error: {0}")]
    LanguageLoad(String),

    #[error("extraction error: {0}")]
    Extraction(String),
}

pub type Result<T> = std::result::Result<T, ParseError>;
