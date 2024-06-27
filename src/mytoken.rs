use chrono::{DateTime, Utc};
use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Display;

use crate::AgentResult;

#[derive(Debug, PartialEq, Hash, Eq, Clone)]
pub enum TokenInfoPerms {
    ///Mytoken `tokeninfo:introspect` value.
    Introspect,
    ///Mytoken `tokeninfo:subtokens` value.
    Subtokens,
    ///Mytoken `tokeninfo:history` value.
    History,
    ///Mytoken `tokeninfo` value.
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

#[derive(Debug, PartialEq, Hash, Eq, Clone)]
pub enum MgmtPerms {
    /// Mytoken `manage_mytoken:list` value.
    List,
    ///Mytoken `manage_mytoken:revoke` value.
    Revoke,
    ///Mytoken `manage_mytoken:history` value.
    History,
    ///Mytoken `manage_mytoken` value.
    All,
}

impl Display for MgmtPerms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::List => write!(f, "manage_mytoken:list"),
            Self::Revoke => write!(f, "manage_mytoken:revoke"),
            Self::History => write!(f, "manage_mytoken:history"),
            Self::All => write!(f, "manage_mytoken"),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum SettingsPerms {
    ///Mytoken `settings:grants:ssh` value.
    Ssh,
    ///Mytoken `settings:grants` value.
    Grants,
    ///Mytoken `settings` value
    All,
    ///Mytoken `read@settings:grants:ssh` value.
    ReadSsh,
    ///Mytoken `read@settings:grants` value.
    ReadGrants,
    ///Mytoken `read@settings` value.
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

#[derive(Hash, PartialEq, Eq, Debug, Clone)]
pub enum Capability {
    AT,
    TokenInfo(TokenInfoPerms),
    MyTokenMgmt(MgmtPerms),
    MyTokenCreate,
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
            Capability::MyTokenMgmt(ref perm) => serializer.serialize_str(&perm.to_string()),
            Capability::MyTokenCreate => serializer.serialize_str("create_mytoken"),
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
            "manage_mytoken" => Ok(Capability::MyTokenMgmt(MgmtPerms::All)),
            "manage_mytoken:list" => Ok(Capability::MyTokenMgmt(MgmtPerms::List)),
            "manage_mytoken:revoke" => Ok(Capability::MyTokenMgmt(MgmtPerms::Revoke)),
            "manage_mytoken:history" => Ok(Capability::MyTokenMgmt(MgmtPerms::History)),
            "create_mytoken" => Ok(Capability::MyTokenCreate),
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
pub enum MyTokenType {
    TOKEN,
    SHORT_TOKEN,
    TRANSER_CODE,
}

#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
#[allow(non_snake_case)]
pub struct Restriction {
    #[serde(with = "chrono::serde::ts_seconds_option")]
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<DateTime<Utc>>,

    #[serde(with = "chrono::serde::ts_seconds_option")]
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    geoip_allow: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    geoip_disallow: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    usages_AT: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    usages_other: Option<u64>,
}

impl Default for Restriction {
    fn default() -> Self {
        Self {
            nbf: None,
            exp: None,
            scope: None,
            audience: None,
            ip: None,
            geoip_allow: None,
            geoip_disallow: None,
            usages_AT: None,
            usages_other: None,
        }
    }
}

#[allow(non_snake_case)]
impl Restriction {
    pub fn new() -> Self {
        Restriction::default()
    }
    pub fn set_nbf(&mut self, nbf: DateTime<Utc>) {
        self.nbf = Some(nbf)
    }
    pub fn set_exp(&mut self, exp: DateTime<Utc>) {
        self.exp = Some(exp)
    }
    pub fn add_scope<T: ToString>(&mut self, scope: T) {
        if let Some(ref mut curr_scope) = self.scope {
            curr_scope.push_str(" ");
            curr_scope.push_str(&scope.to_string());
        } else {
            self.scope = Some(scope.to_string().trim().to_string());
        }
    }
    pub fn add_audiences<I, T>(&mut self, audiences: I)
    where
        I: IntoIterator<Item = T>,
        T: ToString,
    {
        let audiences = audiences
            .into_iter()
            .map(|s| s.to_string())
            .collect::<HashSet<_>>();
        self.audience.get_or_insert_with(Vec::new).extend(audiences)
    }
    pub fn add_ips<I, T>(&mut self, hosts: I)
    where
        I: IntoIterator<Item = T>,
        T: ToString,
    {
        let hosts = hosts
            .into_iter()
            .map(|s| s.to_string())
            .collect::<HashSet<_>>();
        self.ip.get_or_insert_with(Vec::new).extend(hosts);
    }
    pub fn add_geoip_allow<I, T>(&mut self, geoip_allow: I)
    where
        I: IntoIterator<Item = T>,
        T: ToString,
    {
        let geoip_allow = geoip_allow
            .into_iter()
            .map(|s| s.to_string())
            .collect::<HashSet<_>>();
        self.geoip_allow
            .get_or_insert_with(Vec::new)
            .extend(geoip_allow);
    }
    pub fn add_geoip_disallow<I, T>(&mut self, geoip_disallow: I)
    where
        I: IntoIterator<Item = T>,
        T: ToString,
    {
        let geoip_disallow = geoip_disallow
            .into_iter()
            .map(|s| s.to_string())
            .collect::<HashSet<_>>();
        self.geoip_disallow
            .get_or_insert_with(Vec::new)
            .extend(geoip_disallow);
    }
    pub fn set_usage_AT(&mut self, n: u64) {
        self.usages_AT = Some(n);
    }
    pub fn set_usage_other(&mut self, n: u64) {
        self.usages_other = Some(n);
    }
    pub fn builder() -> RestrictionBuilder {
        RestrictionBuilder(Restriction::default())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[allow(non_snake_case)]
pub struct Rotation {
    #[serde(skip_serializing_if = "Option::is_none")]
    on_AT: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    on_other: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    lifetime: Option<u64>, //Seconds I guess

    #[serde(skip_serializing_if = "Option::is_none")]
    auto_revoke: Option<bool>,
}

impl Rotation {
    pub fn builder() -> RotationBuilder {
        RotationBuilder(Self {
            on_AT: None,
            on_other: None,
            lifetime: None,
            auto_revoke: None,
        })
    }
}

pub struct RotationBuilder(Rotation);

#[allow(non_snake_case)]
impl RotationBuilder {
    pub fn set_on_AT(mut self) -> Self {
        self.0.on_AT = Some(true);
        self
    }
    pub fn unset_on_AT(mut self) -> Self {
        self.0.on_AT = Some(false);
        self
    }
    pub fn set_on_other(mut self) -> Self {
        self.0.on_other = Some(true);
        self
    }
    pub fn unset_on_other(mut self) -> Self {
        self.0.on_other = Some(false);
        self
    }
    pub fn set_lifetime(mut self, lifetime: u64) -> Self {
        self.0.lifetime = Some(lifetime);
        self
    }
    pub fn set_auto_revoke(mut self) -> Self {
        self.0.auto_revoke = Some(true);
        self
    }
    pub fn unset_auto_revoke(mut self) -> Self {
        self.0.auto_revoke = Some(false);
        self
    }
    pub fn build(self) -> AgentResult<Rotation> {
        if self.0.on_AT == Some(true) || self.0.on_other == Some(true) {
            return Ok(self.0);
        }
        Err("Failed to build rotation object! on_AT or on_other must be set!".into())
    }
}

pub struct RestrictionBuilder(Restriction);

#[allow(non_snake_case)]
impl RestrictionBuilder {
    pub fn nbf(mut self, nbf: DateTime<Utc>) -> Self {
        self.0.set_nbf(nbf);
        self
    }
    pub fn exp(mut self, exp: DateTime<Utc>) -> Self {
        self.0.set_exp(exp);
        self
    }
    pub fn add_scope<T: ToString>(mut self, scope: T) -> Self {
        self.0.add_scope(scope);
        self
    }
    pub fn add_audiences<I, T>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: ToString,
    {
        self.0.add_audiences(audiences);
        self
    }
    pub fn add_ips<I, T>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: ToString,
    {
        self.0.add_ips(hosts);
        self
    }
    pub fn add_geoip_allow<I, T>(mut self, geoip_allow: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: ToString,
    {
        self.0.add_geoip_allow(geoip_allow);
        self
    }
    pub fn add_geoip_disallow<I, T>(mut self, geoip_disallow: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: ToString,
    {
        self.0.add_geoip_disallow(geoip_disallow);
        self
    }
    pub fn usages_AT(mut self, n: u64) -> Self {
        self.0.set_usage_AT(n);
        self
    }
    pub fn usages_other(mut self, n: u64) -> Self {
        self.0.set_usage_other(n);
        self
    }
    pub fn build(self) -> Restriction {
        self.0
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Profile {
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Option<HashSet<Capability>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    restrictions: Option<HashSet<Restriction>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    rotation: Option<Rotation>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            capabilities: None,
            restrictions: None,
            rotation: None,
        }
    }
}

impl Profile {
    pub fn new() -> Self {
        Profile::default()
    }

    pub fn add_capabilities<'a, I>(&mut self, capabilities: I)
    where
        I: IntoIterator<Item = &'a Capability>,
    {
        if let Some(ref mut caps) = self.capabilities {
            caps.extend(capabilities.into_iter().cloned())
        } else {
            self.capabilities = Some(capabilities.into_iter().cloned().collect())
        }
    }

    pub fn add_restrictions<'a, I>(&mut self, restrictions: I)
    where
        I: IntoIterator<Item = &'a Restriction>,
    {
        if let Some(ref mut rests) = self.restrictions {
            rests.extend(restrictions.into_iter().cloned())
        } else {
            self.restrictions = Some(restrictions.into_iter().cloned().collect())
        }
    }
    pub fn set_rotation(&mut self, rotation: &Rotation) {
        self.rotation = Some(*rotation);
    }
    pub fn builder() -> ProfileBuilder {
        ProfileBuilder(Profile::default())
    }
}

pub struct ProfileBuilder(Profile);

impl ProfileBuilder {
    pub fn add_capabilities<'a, I>(mut self, capabilities: I) -> Self
    where
        I: IntoIterator<Item = &'a Capability>,
    {
        self.0.add_capabilities(capabilities);
        self
    }

    pub fn add_restrictions<'a, I>(mut self, restrictions: I) -> Self
    where
        I: IntoIterator<Item = &'a Restriction>,
    {
        self.0.add_restrictions(restrictions);
        self
    }
    pub fn set_rotation(mut self, rotation: &Rotation) -> Self {
        self.0.set_rotation(rotation);
        self
    }
    pub fn build(self) -> Profile {
        self.0
    }
}
