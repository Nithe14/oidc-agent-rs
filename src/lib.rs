pub mod requests;
pub mod responses;

use requests::{AccessTokenRequest, AccountsRequest, MytokenRequest};
use responses::{
    AccessTokenResponse, AccountsResponse, MytokenResponse, OIDCAgentError, OIDCAgentResponse,
    Status,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::env;
use std::error::Error;
use std::io::prelude::*;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;

type DynResult<T> = Result<T, Box<dyn Error>>;

pub trait Request {}
pub trait Response {}

pub struct Client {
    socket_path: PathBuf,
}

impl Client {
    pub fn new() -> DynResult<Self> {
        let socket_path = env::var("OIDC_SOCK")?;
        Ok(Self {
            socket_path: socket_path.into(),
        })
    }

    pub fn get_socket_path(&self) -> Option<&str> {
        self.socket_path.to_str()
    }

    pub fn get_access_token(&self, account_shortname: &str) -> DynResult<String> {
        let request = AccessTokenRequest::basic(account_shortname);
        let response: AccessTokenResponse = self.get(request)?;
        Ok(response.access_token)
    }

    pub fn get_mytoken(&self, account_shortname: &str) -> DynResult<String> {
        let request = MytokenRequest::basic(account_shortname);
        let response: MytokenResponse = self.get(request)?;
        Ok(response.mytoken)
    }

    pub fn get_loaded_accounts(&self) -> DynResult<Vec<String>> {
        let request = AccountsRequest::new();
        let response: AccountsResponse = self.get(request)?;
        Ok(response.info)
    }

    pub fn get<T, R>(&self, request: T) -> DynResult<R>
    where
        T: Request + Serialize,
        R: Response + DeserializeOwned,
    {
        let mut socket = UnixStream::connect(Path::new(&self.socket_path))?;
        let req = serde_json::to_vec(&request)?;
        socket.write_all(&req)?;

        let mut buffer = Vec::new();
        socket.read_to_end(&mut buffer)?;
        let resp: OIDCAgentResponse = serde_json::from_slice(&buffer)?;
        match resp.status() {
            Status::SUCCESS => {
                let r: R = serde_json::from_slice(&buffer)?;
                Ok(r)
            }
            Status::FAILURE => {
                let r: OIDCAgentError = serde_json::from_slice(&buffer)?;
                Err(Box::new(r))
            }
        }
    }
}
