use std::{collections::HashMap, ops::Deref};

use actix_web::{post, web, HttpRequest, Responder};
use pektin_common::{
    deadpool_redis::redis::AsyncCommands, proto::rr::Name, PektinCommonError, RedisEntry, RrSet,
};
use serde_json::json;

use crate::{
    auth::auth_ok,
    dnssec::{get_dnskey_for_zone, sign_redis_entry},
    errors_and_responses::{auth_err, err, internal_err, success, success_with_toplevel_data},
    types::{AppState, SetRequestBody},
    utils::deabsolute,
    validation::{check_soa, validate_records},
    vault,
};

#[post("/set")]
pub async fn set(
    req: HttpRequest,
    mut req_body: web::Json<SetRequestBody>,
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
            return success_with_toplevel_data("set records", json!([]));
        }

        let mut con = match state.redis_pool.get().await {
            Ok(c) => c,
            Err(_) => return internal_err("No redis connection."),
        };

        let valid = validate_records(&req_body.records);
        if valid.iter().any(|v| v.is_err()) {
            let messages = valid
                .iter()
                .map(|res| res.as_ref().err().map(|e| e.to_string()))
                .collect();
            return err("One or more records were invalid.", messages);
        }

        let (soa_check, new_authoritative_zones) =
            match check_soa(&req_body.records, &mut con).await {
                Ok(s) => s,
                Err(e) => return internal_err(e.to_string()),
            };
        if soa_check.iter().any(|s| s.is_err()) {
            let messages = soa_check
                .iter()
                .map(|res| res.as_ref().err().map(|e| e.to_string()))
                .collect();
            return err(
                "Tried to set one or more records for a zone that does not have a SOA record.",
                messages,
            );
        }

        // TODO factor out into separate function using cached api and confidant token
        let vault_api_token = vault::login_userpass(
            &state.vault_uri,
            &state.vault_user_name,
            &state.vault_password,
        )
        .await
        .unwrap();

        let confidant_token = vault::login_userpass(
            &state.vault_uri,
            &format!("pektin-client-{}-confidant", req_body.client_username),
            &req_body.confidant_password,
        )
        .await
        .unwrap();

        let mut dnskeys_for_new_zones = Vec::with_capacity(new_authoritative_zones.len());
        // TODO store signer tokens per zone
        let mut signer_token = "".into();
        for zone in new_authoritative_zones {
            let signer_password =
                vault::get_signer_pw(&state.vault_uri, &vault_api_token, &confidant_token, &zone)
                    .await
                    .unwrap();

            let zone_str = zone.to_string();
            let zone_str = deabsolute(&zone_str);
            let vault_signer_token = match vault::login_userpass(
                &state.vault_uri,
                &format!(
                    "pektin-signer-{}",
                    idna::domain_to_ascii(zone_str).expect("Couldn't encode zone name")
                ),
                &signer_password,
            )
            .await
            {
                Ok(token) => token,
                Err(e) => return internal_err(e.to_string()),
            };
            signer_token = vault_signer_token.clone();
            let dnskey = get_dnskey_for_zone(&zone, &state.vault_uri, &vault_signer_token).await;
            dnskeys_for_new_zones.push((zone, dnskey));
        }
        if dnskeys_for_new_zones.iter().any(|(_, s)| s.is_err()) {
            let messages = dnskeys_for_new_zones
                .iter()
                .map(|(_, res)| res.as_ref().err().map(|e| e.to_string()))
                .collect();
            return err(
                "Could not set DNSKEY for one or more newly created zones because Vault has no signer for this zone.",
                messages,
            );
        }

        let dnskeys: HashMap<_, _> = dnskeys_for_new_zones
            .into_iter()
            .map(|(zone, res)| (zone, res.unwrap()))
            .collect();

        // we need to append the DNSKEY records to req_body.records now or they won't be signed
        let mut dnskey_records: Vec<_> = dnskeys
            .clone()
            .into_iter()
            .map(|(zone, dnskey)| RedisEntry {
                name: zone,
                // TODO think about DNSKEY TTL
                ttl: 3600,
                rr_set: RrSet::DNSKEY {
                    rr_set: vec![dnskey],
                },
            })
            .collect();
        req_body.records.append(&mut dnskey_records);

        let mut rrsig_records = Vec::with_capacity(req_body.records.len());
        for record in &req_body.records {
            // TODO get the correct zone for each record
            let record_zone = Name::from_ascii("pektin.club.").unwrap();
            let dnskey = match dnskeys.get(&record_zone) {
                Some(dnskey) => dnskey,
                None => continue,
            };
            let rec = sign_redis_entry(
                &record_zone,
                record.clone(),
                dnskey,
                &state.vault_uri,
                &signer_token,
            )
            .await;
            rrsig_records.push(rec);
        }
        if rrsig_records.iter().any(|s| s.is_err()) {
            let messages = rrsig_records
                .iter()
                .map(|res| res.as_ref().err().map(|e| e.to_string()))
                .collect();
            return err("Could not sign one or more records.", messages);
        }
        let mut rrsig_records = rrsig_records
            .into_iter()
            .map(|res| res.unwrap())
            .collect::<Vec<_>>();
        req_body.records.append(&mut rrsig_records);

        // TODO:
        // - where do we store the config whether DNSSEC is enabled? -> DNSSEC is always enabled
        // - sign all records and store the RRSIGs in redis
        // - re-generate and re-sign NSEC records

        let entries: Result<Vec<_>, _> = req_body
            .records
            .iter()
            .map(|e| match e.serialize_for_redis() {
                Ok(ser) => Ok((e.redis_key(), ser)),
                Err(e) => Err(e),
            })
            .collect();
        match entries {
            Err(e) => internal_err(e.to_string()),
            Ok(entries) => match con.set_multiple(&entries).await {
                Ok(()) => {
                    let messages = entries.iter().map(|_| "set record").collect();
                    success("set records", messages)
                }
                Err(e) => internal_err(PektinCommonError::from(e).to_string()),
            },
        }
    } else {
        auth.message.push('\n');
        auth_err(auth.message)
    }
}
