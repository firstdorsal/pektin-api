use std::{collections::HashMap, time::Duration};

use crate::PektinApiResult;
use reqwest::{self};
use serde::Deserialize;

use serde_json::json;

pub async fn get_pear_policy(
    endpoint: &str,
    token: String,
    policy_name: &str,
) -> PektinApiResult<String> {
    let val = get_value(endpoint, token, "pektin-pear-policies", policy_name).await?;

    Ok(val.get_key_value("policy").unwrap().1.to_string())
}

pub async fn get_value(
    endpoint: &str,
    token: String,
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
    endpoint: &str,
    username: &str,
    password: &str,
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

pub async fn get_health(uri: String) -> u16 {
    let res = reqwest::Client::new()
        .get(format!("{}{}", uri, "/v1/sys/health"))
        .timeout(Duration::from_secs(2))
        .send()
        .await;

    res.map(|r| r.status().as_u16()).unwrap_or(0)
}
