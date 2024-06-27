use crate::{
    mytoken::Profile,
    responses::{AccessTokenResponse, AccountsResponse, MyTokenResponse},
    AgentResult, Request,
};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
#[allow(non_camel_case_types)]
pub(crate) enum RequestType {
    ACCESS_TOKEN,
    MYTOKEN,
    LOADED_ACCOUNTS,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccessTokenRequest {
    request: RequestType,

    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<Url>,

    #[serde(skip_serializing_if = "Option::is_none")]
    min_valid_period: Option<u64>, //Always seconds

    #[serde(skip_serializing_if = "Option::is_none")]
    application_hint: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<String>,
}

impl AccessTokenRequest {
    /// Creates new request with only `account` field set.
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

    /// Creates a new `AccessTokenRequestBuilder` to build a request.
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
    type SuccessResponse = AccessTokenResponse;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MyTokenRequest {
    request: RequestType,
    account: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    mytoken_profile: Option<Profile>,

    #[serde(skip_serializing_if = "Option::is_none")]
    application_hint: Option<String>,
}

impl MyTokenRequest {
    /// Creates new request with only `account` field set.
    pub fn basic(account: &str) -> Self {
        Self {
            request: RequestType::MYTOKEN,
            account: account.to_string(),
            mytoken_profile: None,
            application_hint: None,
        }
    }
    /// Creates a new `MyTokenRequestBuilder` to build a request.
    pub fn builder(account: &str) -> MyTokenRequestBuilder {
        MyTokenRequestBuilder(MyTokenRequest::basic(account))
    }
}

impl Request for MyTokenRequest {
    type SuccessResponse = MyTokenResponse;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountsRequest {
    request: RequestType,
}

impl AccountsRequest {
    ///Creates a new request.
    pub fn new() -> Self {
        Self {
            request: RequestType::LOADED_ACCOUNTS,
        }
    }
}

impl Request for AccountsRequest {
    type SuccessResponse = AccountsResponse;
}

pub struct AccessTokenRequestBuilder(AccessTokenRequest);

impl AccessTokenRequestBuilder {
    ///Sets the `account` for the target request.
    pub fn account<T: ToString>(mut self, account: T) -> Self {
        self.0.account = Some(account.to_string());
        self
    }
    ///Tries to set the `issuer` for the target request.
    ///# Errors
    ///the method returns an coresponding [`crate::Error`] if:
    ///- parsing the issuer as an url fails.
    pub fn issuer(mut self, issuer: &str) -> AgentResult<Self> {
        let iss = Url::parse(issuer)?;
        self.0.issuer = Some(iss);
        Ok(self)
    }
    ///Sets the `min_valid_period` for the target request.
    pub fn min_valid_period(mut self, min_valid_period: u64) -> Self {
        self.0.min_valid_period = Some(min_valid_period);
        self
    }
    ///Sets the `application_hint` for the target request.
    pub fn application_hint<T: ToString>(mut self, application_hint: T) -> Self {
        self.0.application_hint = Some(application_hint.to_string());
        self
    }
    ///Add a new scope to the target request. It can take mulitple scopes that should be space separated.
    pub fn add_scope<T: ToString>(mut self, scope: T) -> Self {
        if let Some(ref mut curr_scope) = self.0.scope {
            curr_scope.push_str(" ");
            curr_scope.push_str(&scope.to_string());
        } else {
            self.0.scope = Some(scope.to_string().trim().to_string());
        }
        self
    }
    ///Sets the `audience` for the target request.
    pub fn audience<T: ToString>(mut self, audience: T) -> Self {
        self.0.audience = Some(audience.to_string());
        self
    }
    ///Tries to build the target request from the builder.
    ///# Errors
    ///The method returns an coresponding [`crate::Error`] if:
    ///- neither `account` nor `issuer` is set.
    ///- `account` consists only of withespaces.
    pub fn build(self) -> AgentResult<AccessTokenRequest> {
        if self
            .0
            .account
            .as_ref()
            .is_some_and(|a| !a.trim().is_empty())
            || self.0.issuer.is_some()
        {
            Ok(self.0)
        } else {
            Err("Failed to build request! Account name or issuer required!".into())
        }
    }
}

pub struct MyTokenRequestBuilder(MyTokenRequest);

impl MyTokenRequestBuilder {
    ///Sets the `mytoken_profile` for the target request.
    pub fn mytoken_profile(mut self, mytoken_profile: &Profile) -> Self {
        self.0.mytoken_profile = Some(mytoken_profile.clone());
        self
    }
    ///Sets the `application_hint` for the target request.
    pub fn application_hint<T: ToString>(mut self, application_hint: T) -> Self {
        self.0.application_hint = Some(application_hint.to_string());
        self
    }
    ///Tries to build the target request from the builder.
    ///# Errors
    ///The method returns an coresponding [`crate::Error`] if:
    ///- `account` consists only of withespaces.
    pub fn build(self) -> AgentResult<MyTokenRequest> {
        if self.0.account.trim().is_empty() {
            return Err("Failed to build request! Account name cannot be empty!".into());
        }
        Ok(self.0)
    }
}
