use chrono::{DateTime, Utc};
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
        match *self {
            Self::Introspect => write!(f, "tokeninfo:introspect"),
            Self::Subtokens => write!(f, "tokeninfo:subtokens"),
            Self::History => write!(f, "tokeninfo:history"),
            Self::All => write!(f, "tokeninfo"),
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
        match *self {
            Self::List => write!(f, "manage_mytoken:list"),
            Self::Revoke => write!(f, "manage_mytoken:revoke"),
            Self::History => write!(f, "manage_mytoken:history"),
            Self::All => write!(f, "manage_mytoken"),
        }
    }
}

#[derive(Debug)]
pub enum SettingsPerms {
    Ssh,
    Grants,
    All,
    ReadSsh,
    ReadGrants,
    ReadAll,
}

impl Display for SettingsPerms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Ssh => write!(f, "settings:grants:ssh"),
            Self::Grants => write!(f, "settings:grants"),
            Self::All => write!(f, "settings"),
            Self::ReadSsh => write!(f, "read@settings:grants:ssh"),
            Self::ReadGrants => write!(f, "read@settings:grants"),
            Self::ReadAll => write!(f, "read@settings"),
        }
    }
}

#[derive(Debug)]
pub enum Capability {
    AT,
    TokenInfo(TokenInfoPerms),
    MytokenMgmt(MytokenMgmtPerms),
    MytokenCreate,
    Settings(SettingsPerms),
}

impl Serialize for Capability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Capability::AT => serializer.serialize_str("AT"),
            Capability::TokenInfo(ref perm) => serializer.serialize_str(&perm.to_string()),
            Capability::MytokenMgmt(ref perm) => serializer.serialize_str(&perm.to_string()),
            Capability::MytokenCreate => serializer.serialize_str("create_mytoken"),
            Capability::Settings(ref perm) => serializer.serialize_str(&perm.to_string()),
        }
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "AT" => Ok(Capability::AT),
            "tokeninfo" => Ok(Capability::TokenInfo(TokenInfoPerms::All)),
            "tokeninfo:introspect" => Ok(Capability::TokenInfo(TokenInfoPerms::Introspect)),
            "tokeninfo:subtokens" => Ok(Capability::TokenInfo(TokenInfoPerms::Subtokens)),
            "tokeninfo:history" => Ok(Capability::TokenInfo(TokenInfoPerms::History)),
            "manage_mytoken" => Ok(Capability::MytokenMgmt(MytokenMgmtPerms::All)),
            "manage_mytoken:list" => Ok(Capability::MytokenMgmt(MytokenMgmtPerms::List)),
            "manage_mytoken:revoke" => Ok(Capability::MytokenMgmt(MytokenMgmtPerms::Revoke)),
            "manage_mytoken:history" => Ok(Capability::MytokenMgmt(MytokenMgmtPerms::History)),
            "create_mytoken" => Ok(Capability::MytokenCreate),
            "settings" => Ok(Capability::Settings(SettingsPerms::All)),
            "settings:grants" => Ok(Capability::Settings(SettingsPerms::Grants)),
            "settings:grants:ssh" => Ok(Capability::Settings(SettingsPerms::Ssh)),
            "read@settings" => Ok(Capability::Settings(SettingsPerms::ReadAll)),
            "read@settings:grants" => Ok(Capability::Settings(SettingsPerms::ReadGrants)),
            "read@settings:grants:ssh" => Ok(Capability::Settings(SettingsPerms::ReadSsh)),
            _ => Err(serde::de::Error::custom("Invalid capability!")),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(non_camel_case_types)]
pub enum MytokenType {
    TOKEN,
    SHORT_TOKEN,
    TRANSER_CODE,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Restriction {
    #[serde(with = "chrono::serde::ts_seconds_option")]
    nbf: Option<DateTime<Utc>>,

    #[serde(with = "chrono::serde::ts_seconds_option")]
    exp: Option<DateTime<Utc>>,

    scope: Option<String>,
    audience: Option<Vec<String>>,
    hosts: Option<Vec<String>>,
    geoip_allow: Option<Vec<String>>,
    geoip_disallow: Option<Vec<String>>,
    usages_AT: Option<u64>,
    usages_other: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Rotation {
    on_AT: Option<bool>,
    on_other: Option<bool>,
    lifetime: Option<u64>, //Seconds I guess
    auto_revoke: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct Profile {
    capabilities: Option<Vec<Capability>>,
    restrictions: Option<Vec<Restriction>>,
    rotation: Option<Rotation>,
}

impl Profile {
    pub fn basic() -> Self {
        Self {
            capabilities: Some(vec![Capability::AT]),
            restrictions: None,
            rotation: None,
        }
    }
}
