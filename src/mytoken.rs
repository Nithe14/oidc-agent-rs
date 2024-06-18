use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, PartialEq)]
pub enum TokenInfoPerms {
    Introspect,
    Subtokens,
    History,
    All,
}

impl Display for TokenInfoPerms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Introspect => write!(f, ":introspect"),
            Self::Subtokens => write!(f, ":subtokens"),
            Self::History => write!(f, ":history"),
            Self::All => write!(f, ""),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum MytokenMgmtPerms {
    List,
    Revoke,
    History,
    All,
}

impl Display for MytokenMgmtPerms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::List => write!(f, ":list"),
            Self::Revoke => write!(f, ":revoke"),
            Self::History => write!(f, ":history"),
            Self::All => write!(f, ""),
        }
    }
}

#[derive(Debug)]
pub enum GrantsPerms {
    Ssh,
    Grants,
    All,
}

impl Display for GrantsPerms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ssh => write!(f, ":grants:ssh"),
            Self::Grants => write!(f, ":grants"),
            Self::All => write!(f, ""),
        }
    }
}

#[derive(Debug)]
pub enum Capabilities {
    AT,
    TokenInfo(TokenInfoPerms),
    MytokenMgmt(MytokenMgmtPerms),
    MytokenCreate,
    Settings(GrantsPerms),
}

impl Serialize for Capabilities {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Capabilities::AT => serializer.serialize_str("AT"),
            Capabilities::TokenInfo(ref perm) => {
                let s = format!("tokeninfo{}", perm);
                serializer.serialize_str(&s)
            }
            Capabilities::MytokenMgmt(ref perm) => {
                let s = format!("manage_mytoken{}", perm);
                serializer.serialize_str(&s)
            }
            Capabilities::MytokenCreate => serializer.serialize_str("create_mytoken"),
            Capabilities::Settings(ref perm) => {
                let s = format!("settings{}", perm);
                serializer.serialize_str(&s)
            }
        }
    }
}

impl<'de> Deserialize<'de> for Capabilities {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "AT" => Ok(Capabilities::AT),
            "tokeninfo" => Ok(Capabilities::TokenInfo(TokenInfoPerms::All)),
            "tokeninfo:introspect" => Ok(Capabilities::TokenInfo(TokenInfoPerms::Introspect)),
            "tokeninfo:subtokens" => Ok(Capabilities::TokenInfo(TokenInfoPerms::Subtokens)),
            "tokeninfo:history" => Ok(Capabilities::TokenInfo(TokenInfoPerms::History)),
            "manage_mytoken" => Ok(Capabilities::MytokenMgmt(MytokenMgmtPerms::All)),
            "manage_mytoken:list" => Ok(Capabilities::MytokenMgmt(MytokenMgmtPerms::List)),
            "manage_mytoken:revoke" => Ok(Capabilities::MytokenMgmt(MytokenMgmtPerms::Revoke)),
            "manage_mytoken:history" => Ok(Capabilities::MytokenMgmt(MytokenMgmtPerms::History)),
            "create_mytoken" => Ok(Capabilities::MytokenCreate),
            "settings" => Ok(Capabilities::Settings(GrantsPerms::All)),
            "settings:grants" => Ok(Capabilities::Settings(GrantsPerms::Grants)),
            "settings:grants:ssh" => Ok(Capabilities::Settings(GrantsPerms::Ssh)),
            _ => Err(serde::de::Error::custom("Invalid capability!")),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Profile {
    capabilities: Vec<Capabilities>,
}

impl Profile {
    pub fn basic() -> Self {
        Self {
            capabilities: vec![Capabilities::AT],
        }
    }
}
