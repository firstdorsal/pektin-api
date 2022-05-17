use std::{collections::HashMap, ops::Deref};

use actix_web::{post, web, HttpRequest, Responder};
use pektin_common::{
    deadpool_redis::redis::AsyncCommands, proto::rr::Name, DbEntry, PektinCommonError, RrSet,
};
use serde_json::json;

use crate::{
    auth::auth_ok,
    db::get_or_mget_records,
    dnssec::{get_dnskey_for_zone, sign_db_entry},
    errors_and_responses::{auth_err, err, internal_err, success, success_with_toplevel_data},
    types::{AppState, SetRequestBody},
    utils::deabsolute,
    validation::{check_soa, validate_records},
    vault,
};

#[post("/set")]
pub async fn set(
    req: HttpRequest,
    req_body: web::Json<SetRequestBody>,
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

        let mut con = match state.db_pool.get().await {
            Ok(c) => c,
            Err(_) => return internal_err("No db connection."),
        };

        let mut dnssec_con = match state.db_pool_dnssec.get().await {
            Ok(c) => c,
            Err(_) => return internal_err("No db connection."),
        };

        let valid = validate_records(&req_body.records);
        if valid.iter().any(|v| v.is_err()) {
            let messages = valid
                .iter()
                .map(|res| res.as_ref().err().map(|e| e.to_string()))
                .collect();
            return err("One or more records were invalid.", messages);
        }

        let (soa_check, used_zones, new_authoritative_zones) =
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
        let vault_api_token = match vault::ApiTokenCache::get(
            &state.vault_uri,
            &state.vault_user_name,
            &state.vault_password,
        )
        .await
        {
            Ok(t) => t,
            Err(_) => return internal_err("Couldnt get vault api token"),
        };

        let confidant_token = match vault::ClientTokenCache::get(
            &state.vault_uri,
            &format!("pektin-client-{}-confidant", req_body.client_username),
            &req_body.confidant_password,
        )
        .await
        {
            Ok(t) => t,
            Err(_) => return internal_err("Couldnt get confidant token from vault"),
        };

        let zones_to_fetch_dnskeys_for: Vec<_> = used_zones
            .iter()
            .filter(|zone| !new_authoritative_zones.contains(zone))
            .collect();
        let dnskeys: Vec<_> = if zones_to_fetch_dnskeys_for.is_empty() {
            vec![]
        } else {
            let dnskey_db_keys: Vec<_> = zones_to_fetch_dnskeys_for
                .iter()
                .map(|z| format!("{z}:DNSKEY"))
                .collect();
            match get_or_mget_records(&dnskey_db_keys, &mut con).await {
                Ok(keys) => std::iter::zip(dnskey_db_keys, keys)
                    .map(|(db_key, dnskey)| {
                        let dnskey_entry = dnskey
                            .unwrap_or_else(|| panic!("No DNSKEY entry for zone {} in db", db_key));
                        let dnskey = match dnskey_entry.rr_set {
                            RrSet::DNSKEY { mut rr_set } => {
                                rr_set.pop().expect("DNSKEY record set is empty")
                            }
                            _ => panic!("DNSKEY db entry did not contain a DNSKEY record"),
                        };
                        (dnskey_entry.name.clone(), dnskey)
                    })
                    .collect(),
                Err(e) => return internal_err(e),
            }
        };

        let mut dnskeys_for_new_zones = Vec::with_capacity(new_authoritative_zones.len());
        let mut signer_tokens = HashMap::with_capacity(used_zones.len());

        for zone in new_authoritative_zones {
            let signer_password = match vault::get_signer_pw(
                &state.vault_uri,
                &vault_api_token,
                &confidant_token,
                &zone,
            )
            .await
            {
                Ok(pw) => pw,
                Err(_) => return internal_err(format!("Missing signer password for zone: {zone}")),
            };

            let zone_str = zone.to_string();
            let zone_str = deabsolute(&zone_str);
            let vault_signer_token = match vault::ClientTokenCache::get(
                &state.vault_uri,
                &format!(
                    "pektin-signer-{}",
                    idna::domain_to_ascii(zone_str).expect("Couldn't encode zone name as ascii")
                ),
                &signer_password,
            )
            .await
            {
                Ok(token) => token,
                Err(e) => return internal_err(e.to_string()),
            };
            signer_tokens.insert(zone.clone(), vault_signer_token.clone());
            let dnskey = get_dnskey_for_zone(&zone, &state.vault_uri, &vault_signer_token).await;
            dnskeys_for_new_zones.push((zone, dnskey));
        }

        // we also need to get the signer tokens for all non-new zones
        for zone in zones_to_fetch_dnskeys_for {
            let signer_password = match vault::get_signer_pw(
                &state.vault_uri,
                &vault_api_token,
                &confidant_token,
                zone,
            )
            .await
            {
                Ok(pw) => pw,
                Err(_) => return internal_err(format!("Missing signer password for zone: {zone}")),
            };

            let zone_str = zone.to_string();
            let zone_str = deabsolute(&zone_str);
            let vault_signer_token = match vault::ClientTokenCache::get(
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
            signer_tokens.insert(zone.clone(), vault_signer_token.clone());
        }

        if dnskeys_for_new_zones.iter().any(|(_, s)| s.is_err()) {
            let messages = dnskeys_for_new_zones
                .iter()
                .map(|(_, res)| res.as_ref().err().map(|e| e.to_string()))
                .collect();
            return err(
                "Couldn't set DNSKEY for one or more newly created zones because Vault has no signer for this zone.",
                messages,
            );
        }

        let dnskeys: HashMap<_, _> = dnskeys
            .into_iter()
            .chain(
                dnskeys_for_new_zones
                    .into_iter()
                    .map(|(zone, res)| (zone, res.unwrap())),
            )
            .collect();

        let dnskey_records: Vec<_> = dnskeys
            .clone()
            .into_iter()
            .map(|(zone, dnskey)| DbEntry {
                name: zone,
                // TODO think about DNSKEY TTL
                ttl: 3600,
                rr_set: RrSet::DNSKEY {
                    rr_set: vec![dnskey],
                },
            })
            .collect();
        // TODO once we support separate KSK and ZSK, sign the ZSK with the KSK

        let mut rrsig_records = Vec::with_capacity(req_body.records.len());
        for record in &req_body.records {
            // TODO get the correct zone for each record
            let record_zone = Name::from_ascii("pektin.club.").unwrap();
            let dnskey = match dnskeys.get(&record_zone) {
                Some(dnskey) => dnskey,
                None => continue,
            };
            let rec = sign_db_entry(
                &record_zone,
                record.clone(),
                dnskey,
                &state.vault_uri,
                signer_tokens
                    .get(&record_zone)
                    .expect("No signer token for zone"),
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

        let rrsig_records = rrsig_records
            .into_iter()
            .map(|res| res.unwrap())
            .collect::<Vec<_>>();

        // TODO:
        // - where do we store the config whether DNSSEC is enabled? -> DNSSEC is always enabled
        // - sign all records and store the RRSIGs in db
        // - re-generate and re-sign NSEC records

        let entries: Result<Vec<_>, _> = req_body
            .records
            .iter()
            .chain(dnskey_records.iter())
            .map(|e| match e.serialize_for_db() {
                Ok(ser) => Ok((e.db_key(), ser)),
                Err(e) => Err(e),
            })
            .collect();

        let rrsig_records: Result<Vec<_>, _> = rrsig_records
            .iter()
            .map(|e| match e.serialize_for_db() {
                Ok(ser) => Ok((e.db_key(), ser)),
                Err(e) => Err(e),
            })
            .collect();

        match rrsig_records {
            Err(e) => return internal_err(e.to_string()),
            Ok(rrsig_records) if !rrsig_records.is_empty() => {
                if let Err(e) = dnssec_con.set_multiple::<_, _, ()>(&rrsig_records).await {
                    return internal_err(PektinCommonError::from(e).to_string());
                }
            }
            _ => {
                println!("{:?}", req_body.records);
            }
        }

        // TODO if setting the non-DNSSEC entries fails, we need to remove the DNSSEC entries again
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
