use crate::mytoken::{Capability, MyTokenType, Restriction, Rotation};
use crate::{Response, Token};
use chrono::{DateTime, Utc};
use derive_getters::Getters;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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

#[derive(Serialize, Deserialize, Getters, Debug)]
pub struct OIDCAgentResponse {
    status: Status,
}

#[derive(Serialize, Deserialize, Debug, Getters)]
pub struct AccessTokenResponse {
    access_token: Token,
    issuer: Url,

    #[serde(with = "chrono::serde::ts_seconds")]
    expires_at: DateTime<Utc>,
}

impl Response for AccessTokenResponse {}

#[derive(Serialize, Deserialize, Getters, Debug)]
pub struct MyTokenResponse {
    mytoken: Token,
    mytoken_issuer: Url,
    oidc_issuer: Url,

    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    expires_at: Option<DateTime<Utc>>,
    mytoken_type: Option<MyTokenType>,
    transfer_code: Option<String>,
    expires_in: Option<u64>, //Number of seconds according to the Mytoken documentation
    mom_id: Option<String>,
    capabilities: Option<HashSet<Capability>>,
    restrictions: Option<HashSet<Restriction>>,
    rotation: Option<Rotation>,
}

impl Response for MyTokenResponse {}

#[derive(Serialize, Deserialize, Debug, Getters)]
pub struct AccountsResponse {
    info: Vec<String>,
}

impl Response for AccountsResponse {}
