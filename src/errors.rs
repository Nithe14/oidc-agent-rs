use serde::{Deserialize, Serialize};
use serde_json;
use std::env;
use std::fmt::{Display, Formatter, Result};
use std::io;

#[derive(Serialize, Deserialize, Debug)]
pub struct AgentError {
    error: String,
    info: Option<String>,
}

impl Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(info) = &self.info {
            write!(f, "{}: {}", &self.error, info)
        } else {
            write!(f, "{}", &self.error)
        }
    }
}

impl std::error::Error for AgentError {}

#[derive(Debug)]
pub enum Error {
    EnvVarError(env::VarError),
    IoError(io::Error),
    SerdeError(serde_json::Error),
    AgentError(AgentError),
    ParseError(url::ParseError),
    OtherError(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Error::EnvVarError(e) => write!(f, "Environment variable error: {}", e),
            Error::IoError(e) => write!(f, "IO error: {}", e),
            Error::SerdeError(e) => write!(f, "Serialization/Deserialization error: {}", e),
            Error::AgentError(e) => write!(f, "Agent error: {}", e),
            Error::ParseError(e) => write!(f, "Parse error: Failed to parse URL: {}", e),
            Error::OtherError(e) => write!(f, "Other error: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::EnvVarError(e) => Some(e),
            Error::IoError(e) => Some(e),
            Error::SerdeError(e) => Some(e),
            Error::AgentError(e) => Some(e),
            Error::ParseError(e) => Some(e),
            Error::OtherError(_) => None,
        }
    }
}

impl From<env::VarError> for Error {
    fn from(error: env::VarError) -> Self {
        Error::EnvVarError(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error::SerdeError(error)
    }
}

impl From<AgentError> for Error {
    fn from(error: AgentError) -> Self {
        Error::AgentError(error)
    }
}

impl From<url::ParseError> for Error {
    fn from(error: url::ParseError) -> Self {
        Error::ParseError(error)
    }
}

impl From<&'static str> for Error {
    fn from(error: &'static str) -> Self {
        Error::OtherError(error.to_string())
    }
}
