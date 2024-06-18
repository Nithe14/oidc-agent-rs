use std::fmt::Display;

use serde::{Deserialize, Serialize};
use std::error::Error;
use url::Url;

use crate::Response;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    SUCCESS,
    FAILURE,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(non_camel_case_types)]
pub enum RequestType {
    ACCESS_TOKEN,
    MYTOKEN,
    LOADED_ACCOUNTS,
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

impl Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SUCCESS => write!(f, "success"),
            Self::FAILURE => write!(f, "failure"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct AccessTokenRequest {
    request: RequestType,
    account: Option<String>,
    issuer: Option<Url>,
    min_valid_period: Option<usize>,
    application_hint: Option<String>,
    scope: Option<String>,
    audience: Option<String>,
}

impl AccessTokenRequest {
    pub fn new() -> Self {
        Self {
            request: RequestType::ACCESS_TOKEN,
            account: Some("mytoken".to_string()),
            issuer: None,
            min_valid_period: Some(60),
            application_hint: None,
            scope: Some("openid profile offline_access".to_string()),
            audience: None,
        }
    }
    pub fn basic(account: &str) -> Self {
        Self {
            request: RequestType::ACCESS_TOKEN,
            account: Some(account.to_string()),
            issuer: None,
            min_valid_period: None,
            application_hint: None,
            scope: None,
            audience: None,
        }
    }
}

impl crate::Request for AccessTokenRequest {}
impl crate::Request for MytokenRequest {}

#[derive(Serialize, Deserialize)]
pub struct MytokenRequest {
    request: RequestType,
    account: String,
    mytoken_profile: Option<String>,
    application_hint: Option<String>,
}

impl MytokenRequest {
    pub fn basic(account: &str) -> Self {
        Self {
            request: RequestType::MYTOKEN,
            account: account.to_string(),
            mytoken_profile: None,
            application_hint: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct AccountsRequest {
    request: RequestType,
}

impl AccountsRequest {
    pub fn new() -> Self {
        Self {
            request: RequestType::LOADED_ACCOUNTS,
        }
    }
}

impl crate::Request for AccountsRequest {}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenResponse {
    pub access_token: String,
    issuer: Url,
    expires_at: usize,
}

impl Response for AccessTokenResponse {}
impl Response for MytokenResponse {}
impl Response for AccountsResponse {}

#[derive(Serialize, Deserialize)]
pub struct MytokenResponse {
    pub mytoken: String,
    mytoken_issuer: Url,
    oidc_issuer: Url,
    expires_at: usize,
}

#[derive(Serialize, Deserialize)]
pub struct AccountsResponse {
    pub info: Vec<String>,
}

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
