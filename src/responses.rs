use crate::mytoken::{Capability, MyTokenType, Restriction, Rotation};
use crate::{Response, Token};
use chrono::{DateTime, Utc};
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

#[derive(Serialize, Deserialize, Debug)]
pub struct OIDCAgentResponse {
    status: Status,
}

impl OIDCAgentResponse {
    pub fn status(&self) -> &Status {
        &self.status
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenResponse {
    access_token: Token,
    issuer: Url,

    #[serde(with = "chrono::serde::ts_seconds")]
    expires_at: DateTime<Utc>,
}

impl AccessTokenResponse {
    pub fn access_token(&self) -> &Token {
        &self.access_token
    }
    pub fn issuer(&self) -> &Url {
        &self.issuer
    }
    pub fn expires_at(&self) -> &DateTime<Utc> {
        &self.expires_at
    }
}

impl Response for AccessTokenResponse {}

#[derive(Serialize, Deserialize, Debug)]
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

impl MyTokenResponse {
    pub fn mytoken(&self) -> &Token {
        &self.mytoken
    }
    pub fn mytoken_issuer(&self) -> &Url {
        &self.mytoken_issuer
    }
    pub fn oidc_issuer(&self) -> &Url {
        &self.oidc_issuer
    }
    pub fn expires_at(&self) -> Option<&DateTime<Utc>> {
        self.expires_at.as_ref()
    }
    pub fn mytoken_type(&self) -> Option<&MyTokenType> {
        self.mytoken_type.as_ref()
    }
    pub fn transfer_code(&self) -> Option<&String> {
        self.transfer_code.as_ref()
    }
    pub fn expires_in(&self) -> Option<&u64> {
        self.expires_in.as_ref()
    }
    pub fn mom_id(&self) -> Option<&String> {
        self.mom_id.as_ref()
    }
    pub fn capabilities(&self) -> Option<&HashSet<Capability>> {
        self.capabilities.as_ref()
    }
    pub fn restrictions(&self) -> Option<&HashSet<Restriction>> {
        self.restrictions.as_ref()
    }
    pub fn rotation(&self) -> Option<&Rotation> {
        self.rotation.as_ref()
    }
}

impl Response for MyTokenResponse {}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccountsResponse {
    info: Vec<String>,
}

impl AccountsResponse {
    pub fn info(&self) -> &Vec<String> {
        &self.info
    }
}

impl Response for AccountsResponse {}
