use std::convert::{TryFrom, TryInto};
use std::env;
use std::error::Error;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use thiserror::Error;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use base64::{decode, encode};
use trust_dns_proto::rr::dnssec::rdata::*;
use trust_dns_proto::rr::dnssec::tbs::*;
use trust_dns_proto::rr::dnssec::Algorithm::ECDSAP256SHA256;
use trust_dns_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use reqwest;
use serde::Deserialize;
use serde_json::json;

//use serde::Deserialize;

#[derive(Debug, Error)]
pub enum PektinApiError {
    #[error("Error contacting Redis")]
    Redis(#[from] redis::RedisError),
    #[error("Could not (de)serialize JSON")]
    Json(#[from] serde_json::Error),
    #[error("Environment variable {0} is required, but not set")]
    MissingEnvVar(String),
    #[error("I/O error")]
    IoError(#[from] std::io::Error),
    #[error("Environment variable {0} is invalid")]
    InvalidEnvVar(String),
    #[error("Error contacting Vault")]
    Vault(#[from] reqwest::Error),
    #[error("Error creating DNSSEC signing key on Vault")]
    KeyCreation,
}
pub type PektinApiResult<T> = Result<T, PektinApiError>;

pub fn load_env(default: &str, param_name: &str) -> PektinApiResult<String> {
    let res = if let Ok(param) = env::var(param_name) {
        param
    } else {
        if default.is_empty() {
            return Err(PektinApiError::MissingEnvVar(param_name.into()));
        } else {
            default.into()
        }
    };
    println!("\t{} = {}", param_name, res);
    Ok(res)
}

// generate new tokens and also notify vault
pub fn rotate_tokens(
    vault_uri: &str,
    role_id: &str,
    secret_id: &str,
) -> PektinApiResult<(String, String)> {
    let gss_token = random_string();
    let gssr_token = random_string();
    let vault_token = get_vault_token(vault_uri, role_id, secret_id)?;
    send_tokens_to_vault(&gss_token, &gssr_token, vault_uri, &vault_token)?;

    Ok((gss_token, gssr_token))
}

// creates a crypto random string for use as token
fn random_string() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(100)
        .map(char::from)
        .collect()
}

// send rotated tokens to vault
pub fn send_tokens_to_vault(
    gss_token: &str,
    gssr_token: &str,
    vault_uri: &str,
    vault_token: &str,
) -> PektinApiResult<()> {
    todo!();

    let res = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?
        .post(format!("{}{}", vault_uri, "/v1/pektin-api/gss_token"))
        .header("X-Vault-Token", vault_token)
        .json(&json!({
            "type": "ecdsa-p256",
        }))
        .send()?
        .status();

    // TODO: new error variant for when status is != 200

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
