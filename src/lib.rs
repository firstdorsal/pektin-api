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
use pektin_common::{get_authoritative_zones, RecordData, RedisEntry};
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

pub enum RequestBodys {
    GetRequestBody,
    GetZoneRecordsRequestBody,
    DeleteRequestBody,
    SetRequestBody,
    SearchRequestBody,
    HealthRequestBody,
}

#[derive(Deserialize, Debug, Clone)]
pub struct GetRequestBody {
    token: String,
    keys: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct GetZoneRecordsRequestBody {
    token: String,
    names: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SetRequestBody {
    token: String,
    records: Vec<RedisEntry>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DeleteRequestBody {
    token: String,
    keys: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SearchRequestBody {
    token: String,
    glob: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct HealthRequestBody {
    token: String,
}

#[derive(Debug, Error)]
pub enum PektinApiError {
    #[error("{0}")]
    CommonError(#[from] pektin_common::PektinCommonError),
    #[error("Could not (de)serialize JSON")]
    Json(#[from] serde_json::Error),
    #[error("I/O error")]
    IoError(#[from] std::io::Error),
    #[error("Error contacting Vault")]
    Vault(#[from] reqwest::Error),
    #[error("Error creating DNSSEC signing key on Vault")]
    KeyCreation,
    #[error("Error signaling the pektin-api token rotation to Vault")]
    ApiTokenRotation,
    #[error("No SOA record found for this zone")]
    NoSoaRecord,
    #[error("The queried domain name is invalid")]
    InvalidDomainName,

    // FIXME/TODO:  differ between vault and ribston errors
    #[error("Failed to query Ribston")]
    Ribston,
    #[error("Failed to get combined password")]
    GetCombinedPassword,
    #[error("Failed to get combined password")]
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
}
pub type RecordValidationResult<T> = Result<T, RecordValidationError>;

#[derive(Default, Debug, Clone)]
pub struct PektinApiTokens {
    pub gss_token: String,
    pub gssr_token: String,
}

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
    if !(redis_entry.name.contains(".:") && redis_entry.name.matches(':').count() == 1) {
        return Err(RecordValidationError::InvalidNameFormat);
    }

    if redis_entry.rr_set.is_empty() {
        return Err(RecordValidationError::EmptyRrset);
    }

    for record in redis_entry.clone().rr_set.into_iter() {
        if let Err(err) = record.value.convert() {
            return Err(RecordValidationError::InvalidDataFormat(err));
        }
    }

    let (name, rr_type_str) = redis_entry.name.split_once(":").unwrap();
    if Name::from_utf8(name).is_err() {
        return Err(RecordValidationError::InvalidDnsName(name.into()));
    }

    let rr_type = match RecordType::from_str(rr_type_str) {
        Ok(t) => t,
        Err(_) => {
            return Err(RecordValidationError::InvalidNameRecordType(
                rr_type_str.to_string(),
            ))
        }
    };

    if redis_entry
        .rr_set
        .iter()
        .any(|record| !check_rdata_type(&record.value, rr_type))
    {
        return Err(RecordValidationError::RecordTypeMismatch);
    }

    if rr_type.is_soa() && redis_entry.rr_set.len() != 1 {
        return Err(RecordValidationError::TooManySoas);
    }

    Ok(())
}

// verify that the variant of rdata matches the given RecordType
fn check_rdata_type(rdata: &RecordData, rr_type: RecordType) -> bool {
    match rdata {
        RecordData::A(_) => rr_type == RecordType::A,
        RecordData::AAAA(_) => rr_type == RecordType::AAAA,
        RecordData::CAA { .. } => rr_type == RecordType::CAA,
        RecordData::CNAME(_) => rr_type == RecordType::CNAME,
        RecordData::MX(_) => rr_type == RecordType::MX,
        RecordData::NS(_) => rr_type == RecordType::NS,
        RecordData::OPENPGPKEY(_) => rr_type == RecordType::OPENPGPKEY,
        RecordData::SOA(_) => rr_type == RecordType::SOA,
        RecordData::SRV(_) => rr_type == RecordType::SRV,
        RecordData::TLSA { .. } => rr_type == RecordType::TLSA,
        RecordData::TXT(_) => rr_type == RecordType::TXT,
    }
}

// only call after validate_records() and only if validation succeeded
pub async fn check_soa(records: &[RedisEntry], con: &mut Connection) -> PektinApiResult<()> {
    let contains_soa = records.iter().any(|r| {
        r.rr_set
            .iter()
            .any(|v| matches!(v.value, RecordData::SOA(_)))
    });
    if contains_soa {
        return Ok(());
    }

    let queried_name = Name::from_utf8(records[0].name.split_once(":").unwrap().0)
        .map_err(|_| PektinApiError::InvalidDomainName)?;
    let authoritative_zones = get_authoritative_zones(con).await?;
    if authoritative_zones
        .into_iter()
        .map(|zone| Name::from_utf8(zone).expect("Key in redis is not a valid DNS name"))
        .any(|zone| zone.zone_of(&queried_name))
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

pub async fn auth(
    vault_endpoint: &String,
    vault_api_pw: &String,
    ribston_endpoint: &String,
    client_token: &String,
    request_body: RequestBodys,
    request_info: RequestInfo,
) -> PektinApiResult<bool> {
    let api_token =
        vault::login_userpass(vault_endpoint, &String::from("pektin-api"), vault_api_pw).await?;

    let client_name = vault::lookup_self_name(vault_endpoint, client_token).await?;

    let officer_pw =
        vault::get_officer_pw(vault_endpoint, &api_token, client_token, &client_name).await?;

    let officer_token = vault::login_userpass(
        vault_endpoint,
        &format!("{}-{}", String::from("pektin-officer"), &client_name),
        &officer_pw,
    )
    .await?;

    let client_policy =
        vault::get_ribston_policy(vault_endpoint, &officer_token, &client_name).await?;

    let ribston_answer = ribston::evaluate(
        &ribston_endpoint,
        client_policy,
        RibstonRequestData {
            api_method: request_info.api_method,
            ip: request_info.ip,
            user_agent: request_info.user_agent,
            utc_millis: request_info.utc_millis,
            request_body: request_body,
        },
    )
    .await?;

    Ok(false)
}
