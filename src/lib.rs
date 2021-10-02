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
use deadpool_redis::redis::AsyncCommands;
use deadpool_redis::Connection;
use pektin_common::RedisEntry;
use thiserror::Error;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use base64::{decode, encode};
use pektin_common::proto::rr::dnssec::rdata::*;
use pektin_common::proto::rr::dnssec::tbs::*;
use pektin_common::proto::rr::dnssec::Algorithm::ECDSAP256SHA256;
use pektin_common::proto::rr::{DNSClass, Name, RData, Record, RecordType};

use reqwest;
use serde::Deserialize;
use serde_json::json;

use crypto::util::fixed_time_eq;
//use serde::Deserialize;

#[derive(Debug, Error)]
pub enum PektinApiError {
    #[error("{0}")]
    CommonError(#[from] pektin_common::PektinCommonError),
    #[error("Error contacting Redis")]
    Redis(#[from] deadpool_redis::redis::RedisError),
    #[error("Could not (de)serialize JSON")]
    Json(#[from] serde_json::Error),
    #[error("I/O error")]
    IoError(#[from] std::io::Error),
    #[error("Error contacting Vault")]
    Vault(#[from] reqwest::Error),
    #[error("Error creating DNSSEC signing key on Vault")]
    KeyCreation,
    #[error("Error signaling the pektin-api token rotation to vault ")]
    ApiTokenRotation,
}
pub type PektinApiResult<T> = Result<T, PektinApiError>;

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

// create the signed record in redis
fn create_db_record(signed: String) {}

pub fn auth(token_type: &str, tokens: &PektinApiTokens, request_token: &str) -> bool {
    match token_type {
        "gss" => fixed_time_eq(tokens.gss_token.as_bytes(), request_token.as_bytes()),
        "gssr" => fixed_time_eq(tokens.gssr_token.as_bytes(), request_token.as_bytes()),
        _ => panic!(
            "invalid token type: expected 'gss' or 'gssr', got '{}'",
            token_type
        ),
    }
}

pub fn validate_records(records: &[RedisEntry]) -> Vec<bool> {
    records.iter().map(validate_record).collect()
}

fn validate_record(record: &RedisEntry) -> bool {
    record.name.contains(".:") && record.name.matches(":").count() == 1 && !record.rr_set.is_empty()
}

// verify that the variant of rdata matches the given RecordType
fn check_rdata_type(rdata: &RData, rr_type: RecordType) -> bool {
    match rdata {
        RData::A(_) => rr_type == RecordType::A,
        RData::AAAA(_) => rr_type == RecordType::AAAA,
        RData::ANAME(_) => rr_type == RecordType::ANAME,
        RData::CAA(_) => rr_type == RecordType::CAA,
        RData::CNAME(_) => rr_type == RecordType::CNAME,
        RData::HINFO(_) => rr_type == RecordType::HINFO,
        RData::HTTPS(_) => rr_type == RecordType::HTTPS,
        RData::MX(_) => rr_type == RecordType::MX,
        RData::NAPTR(_) => rr_type == RecordType::NAPTR,
        RData::NULL(_) => rr_type == RecordType::NULL,
        RData::NS(_) => rr_type == RecordType::NS,
        RData::OPENPGPKEY(_) => rr_type == RecordType::OPENPGPKEY,
        RData::OPT(_) => rr_type == RecordType::OPT,
        RData::PTR(_) => rr_type == RecordType::PTR,
        RData::SOA(_) => rr_type == RecordType::SOA,
        RData::SRV(_) => rr_type == RecordType::SRV,
        RData::SSHFP(_) => rr_type == RecordType::SSHFP,
        RData::SVCB(_) => rr_type == RecordType::SVCB,
        RData::TLSA(_) => rr_type == RecordType::TLSA,
        RData::TXT(_) => rr_type == RecordType::TXT,
        RData::DNSSEC(dns_rdata) => match dns_rdata {
            DNSSECRData::DNSKEY(_) => rr_type == RecordType::DNSKEY,
            DNSSECRData::DS(_) => rr_type == RecordType::DS,
            DNSSECRData::KEY(_) => rr_type == RecordType::KEY,
            DNSSECRData::NSEC(_) => rr_type == RecordType::NSEC,
            DNSSECRData::NSEC3(_) => rr_type == RecordType::NSEC3,
            DNSSECRData::NSEC3PARAM(_) => rr_type == RecordType::NSEC3PARAM,
            DNSSECRData::SIG(_) => rr_type == RecordType::SIG,
            DNSSECRData::TSIG(_) => rr_type == RecordType::TSIG,
            DNSSECRData::Unknown { code, rdata } => rr_type == RecordType::Unknown(*code),
            _ => false,
        },
        RData::Unknown { code, rdata } => rr_type == RecordType::Unknown(*code),
        RData::ZERO => rr_type == RecordType::ZERO,
        _ => false,
    }
}

// only call after validate_records() and only if validation succeeded
pub async fn check_soa(records: &[RedisEntry], con: &mut Connection) -> Result<(), String> {
    let contains_soa = records
        .iter()
        .any(|r| r.rr_set.iter().any(|v| matches!(v.value, RData::SOA(_))));
    if contains_soa {
        return Ok(());
    }

    let zone = records[0].name.split_once(":").unwrap().0;
    let soa_key = format!("{}:SOA", zone);
    let soa_res = con.get::<_, String>(&soa_key).await;
    if let Ok(json) = soa_res {
        match serde_json::from_str::<RedisEntry>(&json) {
            Ok(val) => {
                if val.rr_set.is_empty() {
                    Err(
                        "Found SOA key in database, but it contains an empty set of records."
                            .into(),
                    )
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(format!("Could not parse JSON from database: {}.", e)),
        }
    } else {
        Err("No SOA record found for this zone.".into())
    }
}
