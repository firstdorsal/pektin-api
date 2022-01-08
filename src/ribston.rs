use crate::PektinApiError;
use crate::PektinApiResult;

use pektin_common::RedisEntry;
use reqwest::{
    self,
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{net::Ipv6Addr, time::Duration};

pub type RibstonResult<T> = Result<T, PektinApiError>;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RibstonRequestWrapper {
    policy: String,
    input: RibstonRequestData,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RibstonRequestData {
    pub api_method: String,
    pub ip: Option<String>,
    pub utc_millis: u128,
    pub user_agent: String,
    pub redis_entries: Vec<RedisEntry>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RibstonRequestResourceRecord {
    pub name: String,
    pub rr_type: String,
    pub ttl: u16, //TODO is it u64?
    pub values: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct RibstonResultWrapper {
    result: RibstonResponseData,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RibstonResponseData {
    pub return_policy_results: Option<bool>,
    pub api_method: bool,
    pub ip: bool,
    pub utc_millis: bool,
    pub user_agent: bool,
    pub redis_entries: Vec<RibstonResponseResourceRecord>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RibstonResponseError {
    pub error: bool,
    pub message: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RibstonResponseResourceRecord {
    pub name: bool,
    pub rr_set: bool,
}

pub async fn evaluate(
    ribston_uri: &str,
    policy: String,
    to_be_evaluated: RibstonRequestData,
) -> RibstonResult<RibstonResponseData> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    // TODO reuse reqwest::Client

    let eval_response = reqwest::Client::new()
        .post(format!("{}{}", ribston_uri, "/eval-policy"))
        .timeout(Duration::from_secs(2))
        .headers(headers)
        .json::<RibstonRequestWrapper>(&RibstonRequestWrapper {
            policy: policy,
            input: to_be_evaluated,
        })
        .send()
        .await?;

    if eval_response.status() == 200 {
        let data: RibstonResponseData = eval_response.json().await?;
        Ok(data)
    } else {
        let error: RibstonResponseError = eval_response.json().await?;
        Err(PektinApiError::RibstonError)
    }
}

pub async fn get_health(uri: String) -> u16 {
    let res = reqwest::Client::new()
        .get(format!("{}{}", uri, "/health"))
        .timeout(Duration::from_secs(2))
        .send()
        .await;

    res.map(|r| r.status().as_u16()).unwrap_or(0)
}
