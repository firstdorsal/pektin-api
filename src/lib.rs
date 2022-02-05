#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use std::convert::{TryFrom, TryInto};
use std::env;
use std::error::Error;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use actix_web::rt;
use actix_web::rt::time::Instant;
use base64::{decode, encode};
use crypto::util::fixed_time_eq;
use pektin_common::deadpool_redis::redis::AsyncCommands;
use pektin_common::deadpool_redis::Connection;
use pektin_common::proto::rr::dnssec::rdata::*;
use pektin_common::proto::rr::dnssec::tbs::*;
use pektin_common::proto::rr::dnssec::Algorithm::ECDSAP256SHA256;
use pektin_common::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use pektin_common::{get_authoritative_zones, RedisEntry, RrSet};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use ribston::RibstonRequestData;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod ribston;
pub mod vault;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum RequestBody {
    Get { keys: Vec<String> },
    GetZone { names: Vec<String> },
    Set { records: Vec<RedisEntry> },
    Delete { records: Vec<DeleteRecord> },
    Search { glob: String },
    Health,
}

#[derive(Deserialize, Debug, Clone)]
pub struct GetRequestBody {
    pub client_username: String,
    pub confidant_password: String,
    pub keys: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct GetZoneRecordsRequestBody {
    pub client_username: String,
    pub confidant_password: String,
    pub names: Vec<String>,
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
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct DeleteRecord {
    pub name: Name,
    pub rr_type: RrType,
}
#[derive(Deserialize, Debug, Clone)]
pub struct DeleteRequestBody {
    pub client_username: String,
    pub confidant_password: String,
    pub records: Vec<DeleteRecord>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SearchRequestBody {
    pub client_username: String,
    pub confidant_password: String,
    pub glob: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct HealthRequestBody {
    pub client_username: String,
    pub confidant_password: String,
}

#[derive(Debug, Error)]
pub enum PektinApiError {
    #[error("{0}")]
    CommonError(#[from] pektin_common::PektinCommonError),
    #[error("Could not (de)serialize JSON")]
    Json(#[from] serde_json::Error),
    #[error("I/O error")]
    IoError(#[from] std::io::Error),
    // TODO: change this to a manual From impl, also this is not really Vault-specific
    #[error("Error contacting Vault: {0}")]
    Vault(#[from] reqwest::Error),
    #[error("Error creating DNSSEC signing key on Vault")]
    KeyCreation,
    #[error("Error signaling the pektin-api token rotation to Vault")]
    ApiTokenRotation,
    #[error("No SOA record found for this zone")]
    NoSoaRecord,
    #[error("The queried domain name is invalid")]
    InvalidDomainName,
    #[error("Invalid username or password")]
    InvalidCredentials,

    // FIXME/TODO: differentiate between vault and ribston errors
    #[error("Failed to query Ribston")]
    Ribston,
    #[error("Failed to get combined password")]
    GetCombinedPassword,
    #[error("Failed to get ribston policy")]
    GetRibstonPolicy,
}
pub type PektinApiResult<T> = Result<T, PektinApiError>;

#[derive(Debug, Error)]
pub enum RecordValidationError {
    #[error("The record's name has an invalid format")]
    InvalidNameFormat,
    #[error("The record's RR set is empty")]
    EmptyRrset,
    #[error("The record's name contains an invalid record type: '{0}'")]
    InvalidNameRecordType(String),
    #[error("The record's name contains an invalid DNS name: '{0}'")]
    InvalidDnsName(String),
    #[error("The record type of a member of the RR set and in the record's name don't match")]
    RecordTypeMismatch,
    #[error("Too many SOA records (can only set one, duh)")]
    TooManySoas,
    #[error("The record data had an invalid format: {0}")]
    InvalidDataFormat(String),
    #[error("The record's name is not absolute (i.e. the root label at the end is missing)")]
    NameNotAbsolute,
    #[error("The record contains an empty name")]
    EmptyName,
}
pub type RecordValidationResult<T> = Result<T, RecordValidationError>;

#[doc(hidden)]
macro_rules! impl_from_request_body {
    ($req_from:ty, $req_into:ident, $attr:ident) => {
        impl From<$req_from> for RequestBody {
            fn from(value: $req_from) -> Self {
                Self::$req_into { $attr: value.$attr }
            }
        }
    };
    ($req_from:ty, $req_into:ident) => {
        impl From<$req_from> for RequestBody {
            fn from(value: $req_from) -> Self {
                Self::$req_into
            }
        }
    };
}

impl_from_request_body!(GetRequestBody, Get, keys);
impl_from_request_body!(GetZoneRecordsRequestBody, GetZone, names);
impl_from_request_body!(SetRequestBody, Set, records);
impl_from_request_body!(DeleteRequestBody, Delete, records);
impl_from_request_body!(SearchRequestBody, Search, glob);
impl_from_request_body!(HealthRequestBody, Health);

// creates a crypto random string for use as token
pub fn random_string() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(100)
        .map(char::from)
        .collect()
}

// create a record to be signed by vault or local in base64
fn create_to_be_signed(name: &str, record_type: &str) -> String {
    let record = Record::from_rdata(
        Name::from_ascii(&name).unwrap(),
        3600,
        RData::A(Ipv4Addr::from_str("2.56.96.115").unwrap()),
    );
    let sig = SIG::new(
        RecordType::from_str(record_type).unwrap(),
        ECDSAP256SHA256,
        2,
        3600,
        0,
        0,
        0,
        Name::from_ascii(&name).unwrap(),
        Vec::new(),
    );
    let tbs = rrset_tbs_with_sig(
        &Name::from_ascii(&name).unwrap(),
        DNSClass::IN,
        &sig,
        &[record],
    )
    .unwrap();
    encode(tbs)
}

// create the signed record in redis
fn create_db_record(signed: String) {}

pub fn validate_records(records: &[RedisEntry]) -> Vec<RecordValidationResult<()>> {
    records.iter().map(validate_redis_entry).collect()
}

fn validate_redis_entry(redis_entry: &RedisEntry) -> RecordValidationResult<()> {
    if redis_entry.rr_set.is_empty() {
        return Err(RecordValidationError::EmptyRrset);
    }

    if !redis_entry.name.is_fqdn() {
        return Err(RecordValidationError::NameNotAbsolute);
    }

    if let Err(err) = redis_entry.clone().convert() {
        return Err(RecordValidationError::InvalidDataFormat(err));
    }

    let is_soa = matches!(redis_entry.rr_set, RrSet::SOA { .. });
    if is_soa && redis_entry.rr_set.len() != 1 {
        return Err(RecordValidationError::TooManySoas);
    }

    check_for_empty_names(redis_entry)
}

/// Checks that all names in CAA, CNAME, MX, NS, SOA, and SRV records are non-empty (the root label
/// counts as non-empty).
///
/// This is needed because the empty string can be successfully converted to TrustDNS's
/// [`pektin_common::proto::rr::Name`] type.
fn check_for_empty_names(redis_entry: &RedisEntry) -> RecordValidationResult<()> {
    let empty_name = Name::from_ascii("").expect("TrustDNS doesn't allow empty names anymore :)");
    // "" == "." is true, we have to work around that
    let is_empty = |name: &Name| !name.is_root() && (name == &empty_name);

    let ok = match &redis_entry.rr_set {
        RrSet::CAA { rr_set } => rr_set.iter().all(|record| !record.value.is_empty()),
        RrSet::CNAME { rr_set } => rr_set.iter().all(|record| !is_empty(&record.value)),
        RrSet::MX { rr_set } => rr_set
            .iter()
            .all(|record| !is_empty(record.value.exchange())),
        RrSet::NS { rr_set } => rr_set.iter().all(|record| !is_empty(&record.value)),
        RrSet::SOA { rr_set } => rr_set
            .iter()
            .all(|record| !is_empty(record.value.mname()) && !is_empty(record.value.rname())),
        RrSet::SRV { rr_set } => rr_set.iter().all(|record| !is_empty(record.value.target())),
        _ => true,
    };

    if ok {
        Ok(())
    } else {
        Err(RecordValidationError::EmptyName)
    }
}

/// Checks whether the redis entry to be set either contains a SOA record or is for a zone that
/// already has a SOA record.
///
/// This must be called after `validate_records()`, and only if validation succeeded.
pub async fn check_soa(
    entries: &[RedisEntry],
    con: &mut Connection,
) -> PektinApiResult<Vec<PektinApiResult<()>>> {
    let authoritative_zones = get_authoritative_zones(con).await?;
    let mut authoritative_zones: Vec<_> = authoritative_zones
        .into_iter()
        .map(|zone| Name::from_utf8(zone).expect("Key in redis is not a valid DNS name"))
        .collect();
    // if an entry contains a SOA record, add the according zone to the list of authoritative zones
    for entry in entries.iter() {
        if matches!(entry.rr_set, RrSet::SOA { .. }) {
            authoritative_zones.push(entry.name.clone());
        }
    }
    Ok(entries
        .iter()
        .map(|entry| check_soa_for_single_entry(entry, &authoritative_zones))
        .collect())
}

fn check_soa_for_single_entry(
    entry: &RedisEntry,
    authoriative_zones: &[Name],
) -> PektinApiResult<()> {
    // record contains SOA
    if matches!(entry.rr_set, RrSet::SOA { .. }) {
        return Ok(());
    }

    if authoriative_zones
        .iter()
        .any(|auth_zone| auth_zone.zone_of(&entry.name))
    {
        Ok(())
    } else {
        Err(PektinApiError::NoSoaRecord)
    }
}

pub struct RequestInfo {
    pub api_method: String,
    pub ip: Option<String>,
    pub utc_millis: u128,
    pub user_agent: String,
}

pub struct AuthAnswer {
    pub success: bool,
    pub message: String,
}

#[doc(hidden)]
macro_rules! return_if_err {
    ($e:expr, $err_var:ident, $error:expr) => {
        match $e {
            Ok(v) => v,
            Err($err_var) => {
                return AuthAnswer {
                    success: false,
                    message: $error.into(),
                }
            }
        }
    };
}

pub async fn auth(
    vault_endpoint: &str,
    vault_api_pw: &str,
    ribston_endpoint: &str,
    client_username: &str,
    confidant_password: &str,
    ribston_request_data: RibstonRequestData,
) -> AuthAnswer {
    // TODO reuse reqwest::Client, caching, await concurrently where possible

    let api_token = return_if_err!(
        vault::login_userpass(vault_endpoint, "pektin-api", vault_api_pw).await,
        err,
        format!("Could not get Vault token for pektin-api: {}", err)
    );

    let confidant_token = return_if_err!(
        vault::login_userpass(
            vault_endpoint,
            &format!("pektin-client-confidant-{}", client_username),
            confidant_password
        )
        .await,
        err,
        format!("Could not get Vault token for confidant: {}", err)
    );

    let officer_pw = return_if_err!(
        vault::get_officer_pw(
            vault_endpoint,
            &api_token,
            &confidant_token,
            client_username
        )
        .await,
        err,
        format!("Could not get officer password: {}", err)
    );

    let officer_token = return_if_err!(
        vault::login_userpass(
            vault_endpoint,
            &format!("pektin-officer-{}", &client_username),
            &officer_pw,
        )
        .await,
        err,
        format!("Could not get Vault token for officer: {}", err)
    );

    let client_policy = return_if_err!(
        vault::get_ribston_policy(vault_endpoint, &officer_token, client_username).await,
        err,
        format!("Could not get client policy: {}", err)
    );

    if client_policy.contains("@skip-ribston") {
        return AuthAnswer {
            success: true,
            message: "Skipped evaluating policy".into(),
        };
    }

    let ribston_answer = return_if_err!(
        ribston::evaluate(ribston_endpoint, &client_policy, ribston_request_data).await,
        err,
        format!("Could not evaluate client policy: {}", err)
    );

    AuthAnswer {
        success: !ribston_answer.error,
        message: ribston_answer.message,
    }
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

pub fn response(rtype: ResponseType, msg: impl Serialize) -> impl Serialize {
    json!({
        "type": rtype,
        "message": msg,
    })
}

pub fn response_with_data(
    rtype: ResponseType,
    msg: impl Serialize,
    data: impl Serialize,
) -> impl Serialize {
    json!({
        "type": rtype,
        "message": msg,
        "data": data,
    })
}
