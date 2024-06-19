use chrono::{DateTime, Utc};
use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Display;

#[derive(Debug, PartialEq, Hash, Eq)]
pub enum TokenInfoPerms {
    //tokeninfo:introspect
    Introspect,
    //tokeninfo:subtokens
    Subtokens,
    //tokeninfo:history
    History,
    //tokeninfo
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

#[derive(Debug, PartialEq, Hash, Eq)]
pub enum MytokenMgmtPerms {
    //manage_mytoken:list
    List,
    //manage_mytoken:revoke
    Revoke,
    //manage_mytoken:history
    History,
    //manage_mytoken
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

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum SettingsPerms {
    //settings:grants:ssh
    Ssh,
    //settings:grants
    Grants,
    //settings
    All,
    //read@settings:grants:ssh
    ReadSsh,
    //read@settings:grants
    ReadGrants,
    //read@settings
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

#[derive(Hash, PartialEq, Eq, Debug)]
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

#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq)]
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
    hosts: Option<Vec<String>>,

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
            hosts: None,
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
    pub fn add_scope(&mut self, scope: &str) {
        if let Some(ref mut curr_scope) = self.scope {
            curr_scope.push_str(scope);
        } else {
            self.scope = Some(scope.to_string());
        }
    }
    pub fn add_audiences(&mut self, audiences: Vec<String>) {
        if let Some(ref mut curr_audiences) = self.audience {
            curr_audiences.extend(audiences)
        } else {
            self.audience = Some(audiences)
        }
    }
    pub fn add_hosts(&mut self, hosts: Vec<String>) {
        if let Some(ref mut curr_hosts) = self.hosts {
            curr_hosts.extend(hosts)
        } else {
            self.hosts = Some(hosts)
        }
    }
    pub fn add_geoip_allow(&mut self, geoip_allow: Vec<String>) {
        if let Some(ref mut curr_geoip_allow) = self.geoip_allow {
            curr_geoip_allow.extend(geoip_allow)
        } else {
            self.geoip_allow = Some(geoip_allow)
        }
    }
    pub fn add_geoip_disallow(&mut self, geoip_disallow: Vec<String>) {
        if let Some(ref mut curr_geoip_disallow) = self.geoip_disallow {
            curr_geoip_disallow.extend(geoip_disallow)
        } else {
            self.geoip_disallow = Some(geoip_disallow)
        }
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

#[derive(Serialize, Deserialize, Debug)]
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
    pub fn build(self) -> Result<Rotation, &'static str> {
        if self.0.on_AT == Some(true) || self.0.on_other == Some(true) {
            return Ok(self.0);
        }
        Err("Failed to build rotation object! on_AT or on_other must be set!")
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
    pub fn add_scope(mut self, scope: &str) -> Self {
        self.0.add_scope(scope);
        self
    }
    pub fn add_audiences(mut self, audiences: Vec<String>) -> Self {
        self.0.add_audiences(audiences);
        self
    }
    pub fn add_hosts(mut self, hosts: Vec<String>) -> Self {
        self.0.add_hosts(hosts);
        self
    }
    pub fn add_geoip_allow(mut self, geoip_allow: Vec<String>) -> Self {
        self.0.add_geoip_allow(geoip_allow);
        self
    }
    pub fn add_geoip_disallow(mut self, geoip_disallow: Vec<String>) -> Self {
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

#[derive(Serialize, Deserialize, Debug)]
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

    pub fn add_capabilities(&mut self, capabilities: Vec<Capability>) {
        if let Some(ref mut caps) = self.capabilities {
            caps.extend(capabilities)
        } else {
            self.capabilities = Some(capabilities.into_iter().collect())
        }
    }

    pub fn add_restrictions(&mut self, restrictions: Vec<Restriction>) {
        if let Some(ref mut rests) = self.restrictions {
            rests.extend(restrictions)
        } else {
            self.restrictions = Some(restrictions.into_iter().collect())
        }
    }
    pub fn set_rotation(&mut self, rotation: Rotation) {
        self.rotation = Some(rotation);
    }
    pub fn builder() -> ProfileBuilder {
        ProfileBuilder(Profile::default())
    }
}

pub struct ProfileBuilder(Profile);

impl ProfileBuilder {
    pub fn add_capabilities(mut self, capabilities: Vec<Capability>) -> Self {
        self.0.add_capabilities(capabilities);
        self
    }

    pub fn add_restrictions(mut self, restrictions: Vec<Restriction>) -> Self {
        self.0.add_restrictions(restrictions);
        self
    }
    pub fn set_rotation(mut self, rotation: Rotation) -> Self {
        self.0.set_rotation(rotation);
        self
    }
    pub fn build(self) -> Profile {
        self.0
    }
}
