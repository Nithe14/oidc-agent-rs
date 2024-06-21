//! Unix only [`oidc-agent`]( https://indigo-dc.gitbook.io/oidc-agent ) library for Rust
//!
//! # Description
//!
//! This crate is an interface to `oidc-agent` IPC-API.
//!
//! The `oidc-agent` must be running under the user system and OIDC_SOCK must be exported properly.
//!
//! # Obtaining access_token
//! ## Basic usage
//! To obtain access_token by profile shortname from the agent run the following code in `main.rs`:
//! ```
//! use oidc_agent_rs::Agent;
//! use std::error::Error;
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!    let agent = Agent::new()?;
//!    let access_token = agent.get_access_token("profile_shortname")?;
//!
//!    println!("{}", access_token.secret());
//!    Ok(())
//! }
//! ```
//! The `secret()` method is required to obtain token as a `&str` value. Otherwise the Token pseudostruct
//! would be returned.
//!
//! ## Advanced requests
//! To obtain access_token with more advanced options you have to use request builder.
//! [ `AccessTokenRequest` ] has a method to easy build a new request. Then you have to send the request
//! directly to the agent and parse the response.
//!
//! Example:
//! ```
//! use oidc_agent_rs::{requests::AccessTokenRequest, Agent};
//! use std::error::Error;
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     let agent = Agent::new()?;
//!     
//!     //obtaining access_token by issuer only (no shortname needed)
//!     let at_request = AccessTokenRequest::builder()
//!         .issuer("https://issuer.url")?
//!         .min_valid_period(60)
//!         .build()?;
//!
//!     let at_response = agent.send_request(at_request)?;
//!
//!     println!("{}", at_response.access_token().secret());
//!     println!("{}", at_response.issuer());
//!     println!("{}", at_response.expires_at());
//!
//!     Ok(())
//! }
//! ```
//!
//! # Obtaining mytoken
//! ## Basic usage
//! Obtaining mytoken using only profile shortname is very similar to obtaining access_token.
//!
//! Example:
//! ```
//! use oidc_agent_rs::Agent;
//! use std::error::Error;
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     let agent = Agent::new()?;
//!
//!     let mytoken = agent.get_mytoken("mytoken")?;
//!
//!     println!("{}", mytoken.secret());
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Advanced requests
//! If you want to obtain new mytoken using specific Mytoken profile, you have to create new
//! [`mytoken::Profile`] element. This takes 0 or more [`mytoken::Capability`], 0 or more [`mytoken::Restriction`] and one or
//! none [`mytoken::Rotation`]. Empty profile is possible but not recommended.
//!
//! Example:
//!
//!```
//! use oidc_agent_rs::mytoken::{Capability, Profile, Restriction, Rotation, TokenInfoPerms};
//! use oidc_agent_rs::requests::MyTokenRequest;
//! use oidc_agent_rs::Agent;
//! use std::error::Error;
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     let agent = Agent::new()?;
//!     let mut profile = Profile::new();
//!
//!     //basic capabilites
//!     let caps = vec![Capability::AT, Capability::TokenInfo(TokenInfoPerms::All)];
//!
//!     //new restriction
//!     let restriction = Restriction::builder()
//!         .usages_AT(5) //number of mytoken max usages
//!         .add_geoip_allow(vec!["pl", "de"]) //geoip allowed regions
//!         .build();
//!
//!     //basic rotation
//!     let rotation = Rotation::builder().set_on_AT().set_lifetime(1000).build()?;
//!
//!     profile.add_capabilities(&caps);
//!     profile.add_restrictions(&vec![restriction]);
//!     profile.set_rotation(&rotation);
//!
//!     let mt_request = MyTokenRequest::builder("mytoken")
//!         .mytoken_profile(&profile)
//!         .build()?;
//!
//!     let mt_response = agent.send_request(mt_request)?;
//!
//!     println!("{}", mt_response.mytoken().secret());
//!
//!     Ok(())
//! }
//!```

//#![feature(doc_auto_cfg)]
#![cfg(unix)]

pub mod mytoken;
pub mod requests;
pub mod responses;

use requests::{AccessTokenRequest, AccountsRequest, MyTokenRequest};
use responses::{AccessTokenResponse, MyTokenResponse};
use responses::{OIDCAgentError, OIDCAgentResponse, Status};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use std::env;
use std::error::Error;
use std::fmt::Debug;
use std::io::prelude::*;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;

type AgentResult<T> = Result<T, Box<dyn Error>>;

pub trait Request: Serialize {
    type SuccessResponse: Response;
}
pub trait Response: DeserializeOwned {}

#[derive(Debug, Clone)]
pub struct Agent {
    socket_path: PathBuf,
}

impl Agent {
    /// Tries to construct a new `Agent`.
    ///
    /// It attempts to retrieve the socket path from the `OIDC_SOCK` environment variable.
    /// # Errors
    /// The method returns an [`env::VarError`] if the environment variable `OIDC_SOCK` is not set or cannot be retrieved.
    pub fn new() -> Result<Agent, env::VarError> {
        let socket_path = env::var("OIDC_SOCK")?;
        Ok(Self {
            socket_path: socket_path.into(),
        })
    }

    /// Retrives the agent socket path.
    /// # Examples
    /// ```
    /// let agent = Agent::new()?;
    /// assert_eq!(agent.get_socket_path(), Some("/tmp/oidc-agent-service-1000/oidc-agent.sock"))
    /// ```
    pub fn get_socket_path(&self) -> Option<&str> {
        self.socket_path.to_str()
    }

    /// Tries to obtain access_token using only `account_shortname`. No more fields are added to the
    /// request.
    ///
    /// The [`requests::AccessTokenRequest::basic`] is used as a request here.
    /// # Errors
    /// Errors depends on the [`Agent::send_request`] response.
    ///
    /// # Examples
    /// ```
    /// let access_token = agent.get_access_token("shortname")?;
    /// assert_eq!(access_token.secret(), "eyJh...");
    /// ```
    pub fn get_access_token(&self, account_shortname: &str) -> AgentResult<Token> {
        let request = AccessTokenRequest::basic(account_shortname);
        let response = self.send_request(request)?;
        Ok(response.access_token().clone())
    }

    /// The same as [`Agent::get_access_token`], but if response is success, the
    /// [`responses::AccessTokenResponse`] is returned, so you can get additional fields.
    /// # Examples
    /// ```
    /// let at = agent.get_access_token_full("shortname")?;
    /// assert_eq!(at.expires_at(), expiration_date);
    /// assert_eq!(at.issuer(), issuer);
    /// assert_eq!(at.access_token().secret(), access_token);
    /// ```
    pub fn get_access_token_full(
        &self,
        account_shortname: &str,
    ) -> AgentResult<AccessTokenResponse> {
        let request = AccessTokenRequest::basic(account_shortname);
        let response = self.send_request(request)?;
        Ok(response)
    }

    pub fn get_mytoken(&self, account_shortname: &str) -> AgentResult<Token> {
        let request = MyTokenRequest::basic(account_shortname);
        let response = self.send_request(request)?;
        Ok(response.mytoken().clone())
    }

    pub fn get_mytoken_full(&self, account_shortname: &str) -> AgentResult<MyTokenResponse> {
        let request = MyTokenRequest::basic(account_shortname);
        let response = self.send_request(request)?;
        Ok(response)
    }

    pub fn get_loaded_accounts(&self) -> AgentResult<Vec<String>> {
        let request = AccountsRequest::new();
        let response = self.send_request(request)?;
        Ok(response.info().clone())
    }

    pub fn send_request<T>(&self, request: T) -> AgentResult<T::SuccessResponse>
    where
        T: Request,
    {
        let mut socket = UnixStream::connect(Path::new(&self.socket_path))?;
        let req = serde_json::to_vec(&request)?;
        socket.write_all(&req)?;

        let mut buffer = Vec::new();
        socket.read_to_end(&mut buffer)?;
        let resp: OIDCAgentResponse = serde_json::from_slice(&buffer)?;
        match resp.status() {
            Status::SUCCESS => {
                let r: T::SuccessResponse = serde_json::from_slice(&buffer)?;
                Ok(r)
            }
            Status::FAILURE => {
                let r: OIDCAgentError = serde_json::from_slice(&buffer)?;
                Err(Box::new(r))
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Token(String);

impl Token {
    pub fn secret(&self) -> &str {
        &self.0
    }
}

impl Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Token([redacted])")
    }
}
