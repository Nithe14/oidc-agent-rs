use crate::Response;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::Display;
use url::Url;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    SUCCESS,
    FAILURE,
}

impl Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SUCCESS => write!(f, "success"),
            Self::FAILURE => write!(f, "failure"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct OIDCAgentResponse {
    status: Status,
}

impl OIDCAgentResponse {
    pub fn status(self) -> Status {
        self.status.clone()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenResponse {
    pub access_token: String,
    issuer: Url,
    expires_at: usize,
}

impl Response for AccessTokenResponse {}

#[derive(Serialize, Deserialize)]
pub struct MytokenResponse {
    pub mytoken: String,
    mytoken_issuer: Url,
    oidc_issuer: Url,
    expires_at: usize,
}

impl Response for MytokenResponse {}

#[derive(Serialize, Deserialize)]
pub struct AccountsResponse {
    pub info: Vec<String>,
}

impl Response for AccountsResponse {}

#[derive(Serialize, Deserialize, Debug)]
pub struct OIDCAgentError {
    error: String,
    info: Option<String>,
}

impl Display for OIDCAgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(info) = &self.info {
            write!(f, "{}: {}", &self.error, info)
        } else {
            write!(f, "{}", &self.error)
        }
    }
}

impl Error for OIDCAgentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}
