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
use reqwest;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

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

// notify vault (retries until vault was successfully notified)
pub async fn notify_token_rotation(
    gss_token: &str,
    gssr_token: &str,
    vault_uri: &str,
    role_id: &str,
    secret_id: &str,
) {
    let vault_token = loop {
        match get_vault_token(vault_uri, role_id, secret_id) {
            Ok(token) => break token,
            Err(_) => rt::time::sleep(Duration::from_secs(1)).await,
        }
    };
    while let Err(_) = update_tokens_on_vault(gss_token, gssr_token, vault_uri, &vault_token).await
    {
        rt::time::sleep(Duration::from_secs(1)).await;
    }
}

// creates a crypto random string for use as token
pub fn random_string() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(100)
        .map(char::from)
        .collect()
}

async fn update_single_token_on_vault(
    token_name: &str,
    token_value: &str,
    vault_uri: &str,
    vault_token: &str,
) -> PektinApiResult<()> {
    let delete_res_status = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?
        .delete(format!(
            "{}{}{}",
            vault_uri, "/v1/pektin-kv/metadata/", token_name
        ))
        .header("X-Vault-Token", vault_token)
        .send()?
        .status();

    let create_res_status = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?
        .post(format!(
            "{}{}{}",
            vault_uri, "/v1/pektin-kv/data/", token_name
        ))
        .header("X-Vault-Token", vault_token)
        .json(&json!({
            "data": {
                "token": token_value
            }
        }))
        .send()?
        .status();

    if delete_res_status == 204 && create_res_status == 200 {
        Ok(())
    } else {
        Err(PektinApiError::ApiTokenRotation)
    }
}

// send rotated tokens to vault
pub async fn update_tokens_on_vault(
    gss_token: &str,
    gssr_token: &str,
    vault_uri: &str,
    vault_token: &str,
) -> PektinApiResult<()> {
    // TODO: maybe? save token expiration time with the token
    update_single_token_on_vault("gss_token", gss_token, vault_uri, vault_token).await?;
    update_single_token_on_vault("gssr_token", gssr_token, vault_uri, vault_token).await?;
    Ok(())
}

// create a record to be signed by vault or local in base64
fn create_to_be_signed(name: &str, record_type: &str) -> String {
    let record = Record::from_rdata(
        Name::from_ascii(&name).unwrap(),
        3600,
        RData::A(Ipv4Addr::from_str("2.56.96.115").unwrap()),
    );
    let sig = SIG::new(
        RecordType::from_str(&record_type).unwrap(),
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
    return encode(tbs);
}

// take a base64 record and sign it with vault
pub fn sign_with_vault(
    tbs_base64: &str,
    domain: &str,
    vault_uri: &str,
    vault_token: &str,
) -> PektinApiResult<String> {
    let res: String = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?
        .post(format!(
            "{}{}{}{}",
            vault_uri, "/v1/pektin-transit/sign/", domain, "/sha2-256"
        ))
        .header("X-Vault-Token", vault_token)
        .json(&json!({
            "input": tbs_base64,
        }))
        .send()?
        .text()?;
    #[derive(Deserialize, Debug)]
    struct VaultRes {
        data: VaultData,
    }
    #[derive(Deserialize, Debug)]
    struct VaultData {
        signature: String,
    }
    let vault_res = serde_json::from_str::<VaultRes>(&res)?;
    Ok(String::from(&vault_res.data.signature[9..]))
}

// creates a cryptokey on vault
pub fn create_key_vault(domain: &str, vault_uri: &str, vault_token: &str) -> PektinApiResult<()> {
    let res = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?
        .post(format!(
            "{}{}{}",
            vault_uri, "/v1/pektin-transit/keys/", domain
        ))
        .header("X-Vault-Token", vault_token)
        .json(&json!({
            "type": "ecdsa-p256",
        }))
        .send()?
        .status();

    if res == 204 {
        Ok(())
    } else {
        Err(PektinApiError::KeyCreation)
    }
}

// get the vault access token with role and secret id
pub fn get_vault_token(vault_uri: &str, role_id: &str, secret_id: &str) -> PektinApiResult<String> {
    let res: String = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?
        .post(format!("{}{}", vault_uri, "/v1/auth/approle/login"))
        .json(&json!({
            "role_id": role_id,
            "secret_id": secret_id
        }))
        .send()?
        .text()?;
    #[derive(Deserialize, Debug)]
    struct VaultRes {
        auth: VaultAuth,
    }
    #[derive(Deserialize, Debug)]
    struct VaultAuth {
        client_token: String,
    }
    let vault_res = serde_json::from_str::<VaultRes>(&res)?;
    Ok(vault_res.auth.client_token)
}

pub fn get_vault_health(vault_uri: String) -> u16 {
    let res = reqwest::blocking::get(format!("{}{}", vault_uri, "/v1/sys/health"));
    if res.is_err() {
        return 0;
    }
    let res_status = res.unwrap().status();
    return res_status.as_u16();
}

// create the signed record in redis
fn create_db_record(signed: String) {}

pub fn auth(token_type: &str, tokens: &PektinApiTokens, request_token: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(tokens.gss_token.as_bytes());
    let gss_hash = hasher.finalize_reset();
    hasher.update(tokens.gssr_token.as_bytes());
    let gssr_hash = hasher.finalize_reset();
    hasher.update(request_token.as_bytes());
    let request_token_hash = hasher.finalize();

    match token_type {
        "gss" => fixed_time_eq(&gss_hash, &request_token_hash),
        "gssr" => fixed_time_eq(&gssr_hash, &request_token_hash),
        _ => panic!(
            "invalid token type: expected 'gss' or 'gssr', got '{}'",
            token_type
        ),
    }
}

pub fn validate_records(records: &[RedisEntry]) -> Vec<RecordValidationResult<()>> {
    records.iter().map(validate_redis_entry).collect()
}

fn validate_redis_entry(redis_entry: &RedisEntry) -> RecordValidationResult<()> {
    if !(redis_entry.name.contains(".:") && redis_entry.name.matches(":").count() == 1) {
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
