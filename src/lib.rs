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
//! To obtain access_token by account shortname run the following code in `main.rs`:
//! ```
//! use oidc_agent_rs::{Agent, Error};
//!
//! fn main() -> Result<(), Error> {
//!    let agent = Agent::new()?;
//!    let access_token = agent.get_access_token("profile_shortname")?;
//!
//!    println!("{}", access_token.secret());
//!    Ok(())
//! }
//! ```
//! The `secret()` method is required to obtain token as a `&str` value. Otherwise the [ `Token` ] pseudostruct
//! would be returned.
//!
//! ## Asynchronous Usage
//! For asynchronous programming, you need to enable the `async` feature and use the [`crate::async_impl::Agent`].
//! Here’s a basic example of obtaining an access_token asynchronously:
//! ```rust
//! use oidc_agent_rs::async_impl::Agent;
//! use oidc_agent_rs::Error;
//!
//!#[tokio::main]
//!async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!    let agent = Agent::new().await?;
//!
//!    let at = agent.get_access_token("profile_shortname").await?;
//!    println!("{}", at.secret());
//!
//!    Ok(())
//!}
//!```
//! Cargo.toml
//!```toml
//! [dependencies]
//! oidc_agent_rs = { version = "0.2.0", features=["async"]}
//! tokio = { version = "1.39.2", features = ["net", "io-util", "macros", "rt-multi-thread"] }
//! ```
//!
//! ## Advanced requests
//! To obtain access_token with more advanced options you have to use request builder.
//! [ `AccessTokenRequest` ] has a method to easy build a new request. Then you have to send the request
//! directly to the agent and parse the response.
//!
//! Example:
//! ```
//! use oidc_agent_rs::{requests::AccessTokenRequest, Agent, Error};
//!
//! fn main() -> Result<(), Error> {
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
//! Obtaining mytoken using only account shortname is very similar to obtaining access_token.
//!
//! Example:
//! ```
//! use oidc_agent_rs::{Agent, Error};
//!
//! fn main() -> Result<(), Error> {
//!     let agent = Agent::new()?;
//!
//!     let mytoken = agent.get_mytoken("mytoken")?;
//!
//!     println!("{}", mytoken.secret());
//!
//!     Ok(())
//! }
//! ```
//! Once more the secret() method is used to obtain token as a &str value.
//!
//! ## Advanced requests
//! If you want to obtain new mytoken using specific Mytoken profile, you have to create new
//! [`mytoken::Profile`] element. All profile objects documented in the Mytoken documentation are
//! supported. You can add multiple [`mytoken::Capability`] and [`mytoken::Restriction`] elements
//! and single [`mytoken::Rotation`] element to the [`mytoken::Profile`]. Then add the
//! [`mytoken::Profile`] element to the [`requests::MyTokenRequest`] element.
//!
//! Example:
//!
//!```
//! use oidc_agent_rs::mytoken::{Capability, Profile, Restriction, Rotation, TokenInfoPerms};
//! use oidc_agent_rs::requests::MyTokenRequest;
//! use oidc_agent_rs::{Agent, Error};
//!
//! fn main() -> Result<(), Error> {
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

/// An asynchronous Agent API
#[cfg(feature = "async")]
pub mod async_impl;
/// Errors
pub mod errors;
/// Mytoken utils
pub mod mytoken;
/// Requests
pub mod requests;
/// Responses
pub mod responses;

use errors::AgentError;
pub use errors::Error;
use requests::{AccessTokenRequest, AccountsRequest, MyTokenRequest};
use responses::{AccessTokenResponse, MyTokenResponse};
use responses::{OIDCAgentResponse, Status};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use std::env;
use std::fmt::Debug;
use std::io::prelude::*;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;

pub type AgentResult<T> = Result<T, Error>;

pub trait Request: Serialize {
    type SuccessResponse: Response;
}
pub trait Response: DeserializeOwned {}

#[derive(Debug, Clone)]
pub struct Agent {
    socket_path: PathBuf,
}

impl Agent {
    /// Attempts to construct a new `Agent`.
    ///
    /// It attempts to retrieve the socket path from the `OIDC_SOCK` environment variable.
    /// # Errors
    /// The method returns an coresponding [`Error`] if:
    /// - the environment variable `OIDC_SOCK` is not set or cannot be retrieved.
    /// - connection with provided socket is not possible.
    pub fn new() -> AgentResult<Self> {
        let socket_var = env::var("OIDC_SOCK")?;
        let socket_path = Path::new(&socket_var);

        //Check the connection
        UnixStream::connect(socket_path)?;
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

    /// Attempts to obtain access_token using only `account_shortname`. No more fields are added to the
    /// request.
    ///
    /// The [`requests::AccessTokenRequest::basic`] is used as a request here.
    /// # Errors
    /// The same as [`Agent::send_request`].
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

    /// The same as [`Agent::get_access_token`], but if the response is successful, the
    /// [`responses::AccessTokenResponse`] is returned, allowing you to access additional fields.
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

    /// Attempts to obtain [mytoken](https://mytoken-docs.data.kit.edu/) using only `account_shortname`. No more fields are added to the
    /// request.
    ///
    /// The [`requests::MyTokenRequest::basic`] is used as a request here.
    /// # Errors
    /// The same as [`Agent::send_request`].
    ///
    /// # Examples
    /// ```
    /// let mytoken = agent.get_mytoken("shortname")?;
    /// assert_eq!(mytoken.secret(), "eyJh...");
    /// ```
    pub fn get_mytoken(&self, account_shortname: &str) -> AgentResult<Token> {
        let request = MyTokenRequest::basic(account_shortname);
        let response = self.send_request(request)?;
        Ok(response.mytoken().clone())
    }

    /// The same as [`Agent::get_mytoken`], but if the response is successful, the
    /// [`responses::MyTokenResponse`] is returned, allowing you to access additional fields.
    /// # Examples
    /// ```
    /// let mt = agent.get_mytoken_full("shortname")?;
    /// assert_eq!(mt.mytoken_issuer(), mt_issuer);
    /// assert_eq!(mt.oidc_issuer(), issuer);
    /// assert_eq!(mt.capabilites(), vec![Capability::AT]);
    /// assert_eq!(mt.mytoken().secret(), mytoken)
    /// ```
    pub fn get_mytoken_full(&self, account_shortname: &str) -> AgentResult<MyTokenResponse> {
        let request = MyTokenRequest::basic(account_shortname);
        let response = self.send_request(request)?;
        Ok(response)
    }

    /// Attempts to get a list of loaded user accounts. Every account that was loaded via
    /// e.g `oidc-add <account_shortname>` will be returned.
    /// # Errors
    /// The same as [`Agent::send_request`].
    /// # Examples
    /// ```
    /// let accounts = agent.get_loaded_accounts()?;
    /// assert_eq!(accounts, vec!["my_account"]);
    /// ```
    pub fn get_loaded_accounts(&self) -> AgentResult<Vec<String>> {
        let request = AccountsRequest::new();
        let response = self.send_request(request)?;
        Ok(response.info().clone())
    }

    /// Consumes the [`Request`], sends it to the oidc-agent stream socket and attempts to retrives the [`Response`].
    /// # Errors
    /// The method returns an coresponding [`Error`] if:
    /// - connection with socket is not possible anymore,
    /// - cannot write or read the socket,
    /// - the socket response cannot be deserialized,
    /// - the oidc-agnet returned an error.
    /// # Examples
    /// ```
    /// let req = AccessTokenRequest::basic("mytoken");
    /// let resp = agent.send_request(req)?;
    /// assert_eq!(resp.access_token().secret(), access_token);
    /// ```
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
                let r: AgentError = serde_json::from_slice(&buffer)?;
                Err(r.into())
            }
        }
    }
}

/// Token pseudostruct. This struct exists solely for debugging purposes and does not compromise the actual token.
#[derive(Serialize, Deserialize, Clone)]
pub struct Token(String);

impl Token {
    /// Returns the actual token.
    pub fn secret(&self) -> &str {
        &self.0
    }
}

impl Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Token([redacted])")
    }
}
