#![cfg(unix)]

use crate::errors::AgentError;
use crate::requests::{AccessTokenRequest, AccountsRequest, MyTokenRequest};
use crate::responses::{AccessTokenResponse, MyTokenResponse};
use crate::responses::{OIDCAgentResponse, Status};
use crate::AgentResult;
use crate::Request;
use crate::Token;
use std::env;
use std::fmt::Debug;
use std::path::Path;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[derive(Debug, Clone)]
pub struct Agent {
    socket_path: PathBuf,
}

impl Agent {
    /// Asynchronous version of the [`crate::Agent::new()`].
    pub async fn new() -> AgentResult<Self> {
        let socket_var = env::var("OIDC_SOCK")?;
        let socket_path = Path::new(&socket_var);

        //Check the connection
        UnixStream::connect(socket_path).await?;
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

    /// Asynchronous version of [`crate::Agent::get_access_token()`].
    pub async fn get_access_token(&self, account_shortname: &str) -> AgentResult<Token> {
        let request = AccessTokenRequest::basic(account_shortname);
        let response = self.send_request(request).await?;
        Ok(response.access_token().clone())
    }

    /// Asynchronous version of [`crate::Agent::get_access_token_full()`].
    pub async fn get_access_token_full(
        &self,
        account_shortname: &str,
    ) -> AgentResult<AccessTokenResponse> {
        let request = AccessTokenRequest::basic(account_shortname);
        let response = self.send_request(request).await?;
        Ok(response)
    }

    /// Asynchronous version of [`crate::Agent::get_mytoken()`].
    pub async fn get_mytoken(&self, account_shortname: &str) -> AgentResult<Token> {
        let request = MyTokenRequest::basic(account_shortname);
        let response = self.send_request(request).await?;
        Ok(response.mytoken().clone())
    }

    /// Asynchronous version of [`crate::Agent::get_mytoken_full()`].
    pub async fn get_mytoken_full(&self, account_shortname: &str) -> AgentResult<MyTokenResponse> {
        let request = MyTokenRequest::basic(account_shortname);
        let response = self.send_request(request).await?;
        Ok(response)
    }

    /// Asynchronous version of [`crate::Agent::get_loaded_accounts()`].
    pub async fn get_loaded_accounts(&self) -> AgentResult<Vec<String>> {
        let request = AccountsRequest::new();
        let response = self.send_request(request).await?;
        Ok(response.info().clone())
    }

    /// Asynchronous version of [`crate::Agent::send_request()`].
    pub async fn send_request<T>(&self, request: T) -> AgentResult<T::SuccessResponse>
    where
        T: Request,
    {
        let mut socket = UnixStream::connect(Path::new(&self.socket_path)).await?;
        let req = serde_json::to_vec(&request)?;
        socket.write_all(&req).await?;

        let mut buffer = Vec::new();
        socket.read_to_end(&mut buffer).await?;
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
