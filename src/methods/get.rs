use std::{collections::HashMap, ops::Deref};

use actix_web::{post, web, HttpRequest, Responder};
use pektin_common::{proto::rr::Name, PektinCommonError, RedisEntry, RrSet};
use serde_json::json;

use crate::{
    auth_err, auth_ok, check_soa, deabsolute, err, get_dnskey_for_zone, get_or_mget_records,
    internal_err, partial_success_with_data, sign_redis_entry, success, success_with_toplevel_data,
    validate_records, vault, AppState, GetRequestBody, RecordIdentifier, ResponseType,
    SetRequestBody,
};

#[post("/get")]
pub async fn get(
    req: HttpRequest,
    req_body: web::Json<GetRequestBody>,
    state: web::Data<AppState>,
) -> impl Responder {
    let mut auth = auth_ok(
        &req,
        req_body.clone().into(),
        state.deref(),
        &req_body.client_username,
        &req_body.confidant_password,
    )
    .await;

    if auth.success {
        if req_body.records.is_empty() {
            return success_with_toplevel_data("got records", json!([]));
        }

        let mut con = match state.redis_pool.get().await {
            Ok(c) => c,
            Err(_) => return internal_err("No redis connection."),
        };

        let record_keys: Vec<_> = req_body
            .records
            .iter()
            .map(RecordIdentifier::redis_key)
            .collect();

        match get_or_mget_records(&record_keys, &mut con).await {
            Ok(records) => {
                let messages: Vec<_> = records
                    .into_iter()
                    .map(|entry| match entry {
                        Some(e) => (ResponseType::Success, "record found", Some(e)),
                        None => (ResponseType::Error, "no record found", None),
                    })
                    .collect();
                let all_success = messages.iter().all(|(t, _, _)| *t == ResponseType::Success);
                let all_error = messages.iter().all(|(t, _, _)| *t == ResponseType::Error);
                let toplevel_response_type = match (all_success, all_error) {
                    (true, false) => ResponseType::Success,
                    (false, true) => ResponseType::Error,
                    (false, false) => ResponseType::PartialSuccess,
                    (true, true) => unreachable!(),
                };
                let toplevel_message = match toplevel_response_type {
                    ResponseType::Success => "got records",
                    ResponseType::PartialSuccess => "couldn't get all records",
                    ResponseType::Error => "couldn't get records",
                    ResponseType::Ignored => unreachable!(),
                };
                partial_success_with_data(toplevel_response_type, toplevel_message, messages)
            }
            Err(e) => internal_err(e),
        }
    } else {
        auth.message.push('\n');
        auth_err(auth.message)
    }
}
