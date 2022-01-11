use std::{collections::HashMap, time::Duration};

use crate::{PektinApiError, PektinApiResult};
use reqwest::{self};
use serde::{de::Error, Deserialize};

use serde_json::json;

pub async fn get_signer_pw(
    endpoint: &String,
    api_token: &String,
    client_token: &String,
    domain_name: &String,
) -> PektinApiResult<String> {
    let signer_pw_first_half = get_value(
        endpoint,
        client_token,
        &String::from("pektin-signer-passwords-1"),
        domain_name,
    )
    .await?
    .get_key_value("password")
    .ok_or(PektinApiError::GetCombinedPassword)?
    .1
    .to_string();

    let signer_pw_second_half = get_value(
        endpoint,
        api_token,
        &String::from("pektin-signer-passwords-2"),
        domain_name,
    )
    .await?
    .get_key_value("password")
    .ok_or(PektinApiError::GetCombinedPassword)?
    .1
    .to_string();

    Ok(format!("{}{}", signer_pw_first_half, signer_pw_second_half))
}

pub async fn get_officer_pw(
    endpoint: &String,
    api_token: &String,
    client_token: &String,
    client_name: &String,
) -> PektinApiResult<String> {
    let officer_pw_first_half = get_value(
        endpoint,
        client_token,
        &String::from("pektin-officer-passwords-1"),
        client_name,
    )
    .await?
    .get_key_value("password")
    .ok_or(PektinApiError::GetCombinedPassword)?
    .1
    .to_string();

    let officer_pw_second_half = get_value(
        endpoint,
        api_token,
        &String::from("pektin-officer-passwords-2"),
        client_name,
    )
    .await?
    .get_key_value("password")
    .ok_or(PektinApiError::GetCombinedPassword)?
    .1
    .to_string();

    Ok(format!(
        "{}{}",
        officer_pw_first_half, officer_pw_second_half
    ))
}

pub async fn get_ribston_policy(
    endpoint: &String,
    token: &String,
    policy_name: &String,
) -> PektinApiResult<String> {
    let val = get_value(
        endpoint,
        token,
        &String::from("pektin-ribston-policies"),
        policy_name,
    )
    .await?;

    Ok(val
        .get_key_value("policy")
        .ok_or(PektinApiError::GetRibstonPolicy)?
        .1
        .to_string())
}

pub async fn get_value(
    endpoint: &String,
    token: &String,
    kv_engine: &String,
    key: &String,
) -> PektinApiResult<HashMap<String, String>> {
    #[derive(Deserialize, Debug)]
    struct VaultRes {
        data: VaultData,
    }
    #[derive(Deserialize, Debug)]
    struct VaultData {
        data: HashMap<String, String>,
    }

    let vault_res: VaultRes = reqwest::Client::new()
        .get(format!(
            "{}{}{}{}{}",
            endpoint, "/v1/", kv_engine, "/data/", key
        ))
        .timeout(Duration::from_secs(2))
        .header("X-Vault-Token", token)
        .send()
        .await?
        .json()
        .await?;

    Ok(vault_res.data.data)
}

// get the vault access token with role and secret id
pub async fn login_userpass(
    endpoint: &String,
    username: &String,
    password: &String,
) -> PektinApiResult<String> {
    let vault_res: VaultRes = reqwest::Client::new()
        .post(format!(
            "{}{}{}",
            endpoint, "/v1/auth/userpass/login/", username
        ))
        .timeout(Duration::from_secs(2))
        .json(&json!({
            "password": password,
        }))
        .send()
        .await?
        .json()
        .await?;
    #[derive(Deserialize, Debug)]
    struct VaultRes {
        auth: VaultAuth,
    }
    #[derive(Deserialize, Debug)]
    struct VaultAuth {
        client_token: String,
    }
    Ok(vault_res.auth.client_token)
}

// get the vault access token with role and secret id
pub async fn login_approle(
    endpoint: &String,
    role_id: &String,
    secret_id: &String,
) -> PektinApiResult<String> {
    let vault_res: VaultRes = reqwest::Client::new()
        .post(format!("{}{}", endpoint, "/v1/auth/approle/login/"))
        .timeout(Duration::from_secs(2))
        .json(&json!({
            "role_id": role_id,
            "secret_id": secret_id
        }))
        .send()
        .await?
        .json()
        .await?;
    #[derive(Deserialize, Debug)]
    struct VaultRes {
        auth: VaultAuth,
    }
    #[derive(Deserialize, Debug)]
    struct VaultAuth {
        client_token: String,
    }
    Ok(vault_res.auth.client_token)
}

pub async fn get_health(uri: &String) -> u16 {
    let res = reqwest::Client::new()
        .get(format!("{}{}", uri, "/v1/sys/health"))
        .timeout(Duration::from_secs(2))
        .send()
        .await;

    res.map(|r| r.status().as_u16()).unwrap_or(0)
}

// take a base64 record and sign it with vault
pub async fn sign_with_vault(
    tbs_base64: &str,
    domain: &str,
    vault_uri: &str,
    vault_token: &str,
) -> PektinApiResult<String> {
    let res: String = reqwest::Client::new()
        .post(format!(
            "{}{}{}{}",
            vault_uri, "/v1/pektin-transit/sign/", domain, "/sha2-256"
        ))
        .timeout(Duration::from_secs(2))
        .header("X-Vault-Token", vault_token)
        .json(&json!({
            "input": tbs_base64,
        }))
        .send()
        .await?
        .text()
        .await?;
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

pub async fn lookup_self_name(endpoint: &String, token: &String) -> PektinApiResult<String> {
    #[derive(Deserialize, Debug)]
    pub struct LookupSelf {
        data: LookupSelfData,
    }
    #[derive(Deserialize, Debug)]
    pub struct LookupSelfData {
        meta: LookupSelfDataMeta,
    }
    #[derive(Deserialize, Debug)]
    pub struct LookupSelfDataMeta {
        username: String,
    }

    let res: LookupSelf = reqwest::Client::new()
        .get(format!("{}{}", endpoint, "/v1/auth/token/lookup-self"))
        .timeout(Duration::from_secs(2))
        .header("X-Vault-Token", token)
        .send()
        .await?
        .json()
        .await?;
    Ok(res.data.meta.username)
}
