use std::{collections::HashMap, time::Duration};

use crate::{deabsolute, PektinApiError, PektinApiResult};
use data_encoding::BASE64;
use p256::ecdsa::Signature;
use pektin_common::proto::rr::{dnssec::TBS, Name};
use reqwest::{self, StatusCode};
use serde::{de::Error, Deserialize};

use serde_json::json;

pub async fn get_signer_pw(
    endpoint: &str,
    api_token: &str,
    confidant_token: &str,
    zone: &Name,
) -> PektinApiResult<String> {
    let zone = zone.to_string();
    let zone = deabsolute(&zone);
    let signer_pw_first_half =
        get_kv_value(endpoint, confidant_token, "pektin-signer-passwords-1", zone)
            .await?
            .get_key_value("password")
            .ok_or(PektinApiError::GetCombinedPassword)?
            .1
            .to_string();

    let signer_pw_second_half =
        get_kv_value(endpoint, api_token, "pektin-signer-passwords-2", zone)
            .await?
            .get_key_value("password")
            .ok_or(PektinApiError::GetCombinedPassword)?
            .1
            .to_string();

    Ok(format!("{}{}", signer_pw_first_half, signer_pw_second_half))
}

pub async fn get_policy(endpoint: &str, token: &str, policy_name: &str) -> PektinApiResult<String> {
    let val = get_kv_value(endpoint, token, "pektin-policies", policy_name).await?;

    Ok(val
        .get_key_value("ribstonPolicy")
        .ok_or(PektinApiError::GetRibstonPolicy)?
        .1
        .to_string())
}

pub async fn get_kv_value(
    endpoint: &str,
    token: &str,
    kv_engine: &str,
    key: &str,
) -> PektinApiResult<HashMap<String, String>> {
    #[derive(Deserialize, Debug)]
    struct VaultRes {
        data: VaultData,
    }
    #[derive(Deserialize, Debug)]
    struct VaultData {
        data: HashMap<String, String>,
    }

    let vault_res = reqwest::Client::new()
        .get(format!("{}/v1/{}/data/{}", endpoint, kv_engine, key))
        .timeout(Duration::from_secs(2))
        .header("X-Vault-Token", token)
        .send()
        .await?;
    let vault_res = vault_res.text().await?;
    //dbg!(&vault_res);
    let vault_res: VaultRes = serde_json::from_str(&vault_res)?;

    Ok(vault_res.data.data)
}

// get the vault access token with role and secret id
pub async fn login_userpass(
    endpoint: &str,
    username: &str,
    password: &str,
) -> PektinApiResult<String> {
    let vault_res = reqwest::Client::new()
        .post(format!(
            "{}{}{}",
            endpoint, "/v1/auth/userpass/login/", username
        ))
        .timeout(Duration::from_secs(2))
        .json(&json!({
            "password": password,
        }))
        .send()
        .await?;
    let vault_res = vault_res.text().await?;
    // dbg!(&vault_res);
    let vault_res: VaultRes =
        serde_json::from_str(&vault_res).map_err(|_| PektinApiError::InvalidCredentials)?;
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
    endpoint: &str,
    role_id: &str,
    secret_id: &str,
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

pub async fn get_health(uri: &str) -> u16 {
    let res = reqwest::Client::new()
        .get(format!("{}{}", uri, "/v1/sys/health"))
        .timeout(Duration::from_secs(2))
        .send()
        .await;

    res.map(|r| r.status().as_u16()).unwrap_or(0)
}

/// returns all keys for the zone in PEM format, sorted in the order of their index in the vault response
///
/// you probably want to use the last of the returned keys
// TODO this is just for testing, in the future we will need to get the signer password and token
pub async fn get_zone_dnssec_keys(
    zone: &Name,
    vault_uri: &str,
    vault_token: &str,
) -> PektinApiResult<Vec<String>> {
    let zone = zone.to_string();
    let zone = deabsolute(&zone);
    let target_url = format!("{}/v1/pektin-transit/keys/{}", vault_uri, zone);
    dbg!(&target_url);
    let res: String = reqwest::Client::new()
        .get(target_url)
        .timeout(Duration::from_secs(2))
        .header("X-Vault-Token", vault_token)
        .send()
        .await?
        .text()
        .await?;
    dbg!(&res);

    #[derive(Deserialize, Debug)]
    struct VaultRes {
        data: VaultData,
    }
    #[derive(Deserialize, Debug)]
    struct VaultData {
        keys: HashMap<String, VaultKey>,
    }
    #[derive(Deserialize, Debug)]
    struct VaultKey {
        /// in PEM format
        public_key: String,
    }

    let vault_res = serde_json::from_str::<VaultRes>(&res)?;
    let mut keys_with_index: Vec<_> = vault_res
        .data
        .keys
        .into_iter()
        .map(|(index, key)| {
            (
                index
                    .parse::<usize>()
                    .expect("vault key index was not a number"),
                key.public_key,
            )
        })
        .collect();
    keys_with_index.sort_by_key(|(index, _)| *index);
    Ok(keys_with_index.into_iter().map(|(_, key)| key).collect())
}

/// take a base64 ([`data_encoding::BASE64`](https://docs.rs/data-encoding/2.3.2/data_encoding/constant.BASE64.html)) record and sign it with vault
/// `zone` SHOULD NOT end with '.', if it does, the trailing '.' will be silently removed
pub async fn sign_with_vault(
    tbs: &TBS,
    zone: &Name,
    vault_uri: &str,
    vault_token: &str,
) -> PektinApiResult<Vec<u8>> {
    let zone = zone.to_string();
    let zone = deabsolute(&zone);
    let tbs_base64 = BASE64.encode(tbs.as_ref());
    let post_target = format!(
        "{}{}{}{}",
        vault_uri, "/v1/pektin-transit/sign/", zone, "/sha2-256"
    );
    dbg!(&post_target);
    let res: String = reqwest::Client::new()
        .post(post_target)
        .timeout(Duration::from_secs(2))
        .header("X-Vault-Token", vault_token)
        .json(&json!({
            "input": tbs_base64,
        }))
        .send()
        .await?
        .text()
        .await?;
    dbg!(&res);

    #[derive(Deserialize, Debug)]
    struct VaultRes {
        data: VaultData,
    }
    #[derive(Deserialize, Debug)]
    struct VaultData {
        signature: String,
    }

    let vault_res = serde_json::from_str::<VaultRes>(&res)?;

    // each signature from vault starts with "vault:v1:", which we don't want
    let sig_bytes = BASE64.decode(&vault_res.data.signature.as_bytes()[9..])?;

    // vault returns the signature encoded as ASN.1 DER, but we want the raw encoded point
    // coordinates
    let sig = Signature::from_der(&sig_bytes).map_err(|_| PektinApiError::InvalidSigFromVault)?;
    Ok(sig.to_vec())
}

pub async fn lookup_self_name(endpoint: &str, token: &str) -> PektinApiResult<String> {
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
