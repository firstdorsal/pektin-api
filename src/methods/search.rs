use std::{collections::HashMap, ops::Deref};

use actix_web::{post, web, HttpRequest, Responder};
use pektin_common::{
    deadpool_redis::redis::AsyncCommands, proto::rr::Name, PektinCommonError, RedisEntry, RrSet,
};
use serde_json::json;

use crate::{
    auth_err, auth_ok, check_soa, deabsolute, err, get_dnskey_for_zone, internal_err,
    partial_success_with_data, sign_redis_entry, success, success_with_toplevel_data,
    validate_records, vault, AppState, Glob, RecordIdentifier, ResponseType, SearchRequestBody,
    SetRequestBody,
};

#[post("/search")]
pub async fn search(
    req: HttpRequest,
    req_body: web::Json<SearchRequestBody>,
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
        if req_body.globs.is_empty() {
            return success_with_toplevel_data("Searched keys", json!([]));
        }

        let valid: Vec<_> = req_body.globs.iter().map(Glob::validate).collect();
        if valid.iter().any(|s| s.is_err()) {
            let messages = valid
                .iter()
                .map(|res| res.as_ref().err().map(|e| e.to_string()))
                .collect();
            return err("One or more globs were invalid.", messages);
        }

        let mut con = match state.redis_pool.get().await {
            Ok(c) => c,
            Err(_) => return internal_err("No redis connection."),
        };

        let mut found_keys = Vec::with_capacity(req_body.globs.len());
        for glob in &req_body.globs {
            match con.keys::<_, Vec<String>>(&glob.as_redis_glob()).await {
                Ok(keys) => {
                    let records: Result<Vec<_>, _> =
                        keys.iter().map(RecordIdentifier::from_redis_key).collect();
                    match records {
                        Ok(r) => found_keys.push((ResponseType::Success, "Searched glob", r)),
                        Err(e) => return internal_err(e),
                    }
                }
                Err(_) => return internal_err("Could not search the database."),
            }
        }
        partial_success_with_data(ResponseType::Success, "Searched globs", found_keys)
    } else {
        auth.message.push('\n');
        auth_err(auth.message)
    }
}
