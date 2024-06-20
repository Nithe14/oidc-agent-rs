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

pub struct Agent {
    socket_path: PathBuf,
}

impl Agent {
    pub fn new() -> Result<Agent, env::VarError> {
        let socket_path = env::var("OIDC_SOCK")?;
        Ok(Self {
            socket_path: socket_path.into(),
        })
    }

    pub fn get_socket_path(&self) -> Option<&str> {
        self.socket_path.to_str()
    }

    pub fn get_access_token(&self, account_shortname: &str) -> AgentResult<Token> {
        let request = AccessTokenRequest::basic(account_shortname);
        let response = self.send_request(request)?;
        Ok(response.access_token().clone())
    }

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
