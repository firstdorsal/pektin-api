use pektin_common::{deadpool_redis::Pool, proto::rr::Name, RedisEntry};
use serde::{Deserialize, Serialize};

use crate::impl_from_request_body;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RecordIdentifier {
    pub name: Name,
    pub rr_type: RrType,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum RequestBody {
    Get { records: Vec<RecordIdentifier> },
    GetZoneRecords { names: Vec<Name> },
    Set { records: Vec<RedisEntry> },
    Delete { records: Vec<RecordIdentifier> },
    Search { globs: Vec<Glob> },
    Health,
}

#[derive(Deserialize, Debug, Clone)]
pub struct GetRequestBody {
    pub client_username: String,
    pub confidant_password: String,
    pub records: Vec<RecordIdentifier>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct GetZoneRecordsRequestBody {
    pub client_username: String,
    pub confidant_password: String,
    pub names: Vec<Name>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SetRequestBody {
    pub client_username: String,
    pub confidant_password: String,
    pub records: Vec<RedisEntry>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub enum RrType {
    A,
    AAAA,
    CAA,
    CNAME,
    MX,
    NS,
    OPENPGPKEY,
    SOA,
    SRV,
    TLSA,
    TXT,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DeleteRequestBody {
    pub client_username: String,
    pub confidant_password: String,
    pub records: Vec<RecordIdentifier>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Glob {
    pub name_glob: String,
    pub rr_type_glob: String,
}
#[derive(Deserialize, Debug, Clone)]
pub struct SearchRequestBody {
    pub client_username: String,
    pub confidant_password: String,
    pub globs: Vec<Glob>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct HealthRequestBody {
    pub client_username: String,
    pub confidant_password: String,
}

pub struct AppState {
    pub redis_pool: Pool,
    pub vault_uri: String,
    pub ribston_uri: String,
    pub vault_password: String,
    pub skip_auth: String,
}

impl_from_request_body!(GetRequestBody, Get, records);
impl_from_request_body!(GetZoneRecordsRequestBody, GetZoneRecords, names);
impl_from_request_body!(SetRequestBody, Set, records);
impl_from_request_body!(DeleteRequestBody, Delete, records);
impl_from_request_body!(SearchRequestBody, Search, globs);
impl_from_request_body!(HealthRequestBody, Health);

pub struct RequestInfo {
    pub api_method: String,
    pub ip: Option<String>,
    pub utc_millis: u128,
    pub user_agent: String,
}

#[derive(Debug)]
pub struct AuthAnswer {
    pub success: bool,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq)]
pub enum ResponseType {
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "partial-success")]
    PartialSuccess,
    #[serde(rename = "ignored")]
    Ignored,
    #[serde(rename = "error")]
    Error,
}
