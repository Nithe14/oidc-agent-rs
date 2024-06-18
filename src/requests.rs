use crate::Request;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(non_camel_case_types)]
pub enum RequestType {
    ACCESS_TOKEN,
    MYTOKEN,
    LOADED_ACCOUNTS,
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

impl Request for AccessTokenRequest {}

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

impl Request for MytokenRequest {}

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

impl Request for AccountsRequest {}
