use crate::{
    mytoken::Profile,
    responses::{AccessTokenResponse, AccountsResponse, MytokenResponse},
    Request,
};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
#[allow(non_camel_case_types)]
pub enum RequestType {
    ACCESS_TOKEN,
    MYTOKEN,
    LOADED_ACCOUNTS,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenRequest {
    request: RequestType,
    account: Option<String>,
    issuer: Option<Url>,
    min_valid_period: Option<u64>, //Always seconds
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

    pub fn builder() -> AccessTokenRequestBuilder {
        AccessTokenRequestBuilder(Self {
            request: RequestType::ACCESS_TOKEN,
            account: None,
            issuer: None,
            min_valid_period: None,
            application_hint: None,
            scope: None,
            audience: None,
        })
    }
}

impl Request for AccessTokenRequest {
    type Response = AccessTokenResponse;
}

#[derive(Serialize, Deserialize)]
pub struct MytokenRequest {
    request: RequestType,
    account: String,
    mytoken_profile: Option<Profile>,
    application_hint: Option<String>,
}

impl MytokenRequest {
    pub fn basic(account: &str) -> Self {
        Self {
            request: RequestType::MYTOKEN,
            account: account.to_string(),
            mytoken_profile: Some(Profile::basic()),
            application_hint: None,
        }
    }
    pub fn builder(account: &str) -> MytokenRequestBuilder {
        MytokenRequestBuilder(Self {
            request: RequestType::MYTOKEN,
            account: account.to_string(),
            mytoken_profile: None,
            application_hint: None,
        })
    }
}

impl Request for MytokenRequest {
    type Response = MytokenResponse;
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

impl Request for AccountsRequest {
    type Response = AccountsResponse;
}

pub struct AccessTokenRequestBuilder(AccessTokenRequest);

impl AccessTokenRequestBuilder {
    pub fn account(mut self, account: &str) -> Self {
        self.0.account = Some(account.to_string());
        self
    }
    pub fn issuer(mut self, issuer: &str) -> Result<Self, url::ParseError> {
        let iss = Url::parse(issuer)?;
        self.0.issuer = Some(iss);
        Ok(self)
    }
    pub fn min_valid_period(mut self, min_valid_period: u64) -> Self {
        self.0.min_valid_period = Some(min_valid_period);
        self
    }
    pub fn application_hint(mut self, application_hint: &str) -> Self {
        self.0.application_hint = Some(application_hint.to_string());
        self
    }
    pub fn add_scope(mut self, scope: &str) -> Self {
        if let Some(ref mut curr_scope) = self.0.scope {
            curr_scope.push_str(scope);
        } else {
            self.0.scope = Some(scope.to_string());
        }
        self
    }
    pub fn scopes(mut self, scopes: &str) -> Self {
        self.0.scope = Some(scopes.to_string());
        self
    }
    pub fn audience(mut self, audience: &str) -> Self {
        self.0.audience = Some(audience.to_string());
        self
    }
    pub fn build(self) -> Result<AccessTokenRequest, &'static str> {
        if self.0.account.is_some() || self.0.issuer.is_some() {
            Ok(AccessTokenRequest {
                request: RequestType::ACCESS_TOKEN,
                account: self.0.account,
                issuer: self.0.issuer,
                min_valid_period: self.0.min_valid_period,
                application_hint: self.0.application_hint,
                scope: self.0.scope,
                audience: self.0.audience,
            })
        } else {
            Err("Failed to build request! Account name or issuer required!")
        }
    }
}

pub struct MytokenRequestBuilder(MytokenRequest);

impl MytokenRequestBuilder {
    pub fn mytoken_profile(mut self, mytoken_profile: Profile) -> Self {
        self.0.mytoken_profile = Some(mytoken_profile);
        self
    }
    pub fn application_hint(mut self, application_hint: &str) -> Self {
        self.0.application_hint = Some(application_hint.to_string());
        self
    }
    pub fn build(self) -> Result<MytokenRequest, &'static str> {
        if self.0.account.trim().is_empty() {
            return Err("Failed to build request! Account name cannot be empty!");
        }
        Ok(MytokenRequest {
            request: RequestType::MYTOKEN,
            account: self.0.account,
            mytoken_profile: self.0.mytoken_profile,
            application_hint: self.0.application_hint,
        })
    }
}
