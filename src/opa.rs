use pektin_api::PektinApiError;
use reqwest::{
    self,
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
};
use serde::{Deserialize, Serialize};
use std::{net::Ipv6Addr, time::Duration};

pub type OpaResult<T> = Result<T, PektinApiError>;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct OpaRequestData {
    pub domain: String,
    pub api_methods: String,
    pub rr_types: String,
    pub value: String,
    pub ip: Ipv6Addr,
    pub utc_millis: u128,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct OpaResponseData {
    pub domain: bool,
    pub api_methods: bool,
    pub rr_types: bool,
    pub value: bool,
    pub ip: bool,
    pub utc_millis: bool,
}

pub async fn evaluate(
    opa_uri: &str,
    policy: &str,
    to_be_evaluated: OpaRequestData,
) -> OpaResult<OpaResponseData> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));

    let create_policy: u16 = reqwest::Client::new()
        .put(format!("{}{}", opa_uri, "/v1/policies/run"))
        .timeout(Duration::from_secs(2))
        .headers(headers)
        .body(policy.to_string())
        .send()
        .await?
        .status()
        .as_u16();

    if create_policy != 200 {
        return Err(PektinApiError::OpaError);
    }

    let eval_response: OpaResponseData = reqwest::Client::new()
        .post(format!("{}{}", opa_uri, "/"))
        .timeout(Duration::from_secs(2))
        .json::<OpaRequestData>(&to_be_evaluated)
        .send()
        .await?
        .json()
        .await?;

    Ok(eval_response)
}
