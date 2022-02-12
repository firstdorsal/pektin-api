use actix_cors::Cors;
use actix_web::error::{ErrorBadRequest, JsonPayloadError};
use actix_web::{post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use anyhow::{bail, Context};
use dotenv::dotenv;
use pektin_api::ribston::RibstonRequestData;
use pektin_api::*;
use pektin_common::deadpool_redis::redis::{AsyncCommands, Client, FromRedisValue, Value};
use pektin_common::deadpool_redis::{self, Connection, Pool};
use pektin_common::proto::rr::Name;
use pektin_common::{load_env, PektinCommonError, RedisEntry};
use serde::Serialize;
use serde_json::json;
use std::ops::Deref;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    pub bind_address: String,
    pub bind_port: u16,
    pub redis_hostname: String,
    pub redis_username: String,
    pub redis_password: String,
    pub redis_port: u16,
    pub vault_uri: String,
    pub ribston_uri: String,
    pub vault_password: String,
    pub skip_auth: String,
    pub use_policies: String,
}

struct AppState {
    redis_pool: Pool,
    vault_uri: String,
    ribston_uri: String,
    vault_password: String,
    skip_auth: String,
}

impl Config {
    pub fn from_env() -> PektinApiResult<Self> {
        Ok(Self {
            bind_address: load_env("::", "BIND_ADDRESS", false)?,
            bind_port: load_env("80", "BIND_PORT", false)?
                .parse()
                .map_err(|_| pektin_common::PektinCommonError::InvalidEnvVar("BIND_PORT".into()))?,
            redis_hostname: load_env("pektin-redis", "REDIS_HOSTNAME", false)?,
            redis_port: load_env("6379", "REDIS_PORT", false)?
                .parse()
                .map_err(|_| {
                    pektin_common::PektinCommonError::InvalidEnvVar("REDIS_PORT".into())
                })?,
            redis_username: load_env("r-pektin-api", "REDIS_USERNAME", false)?,
            redis_password: load_env("", "REDIS_PASSWORD", true)?,
            vault_uri: load_env("http://pektin-vault:80", "VAULT_URI", false)?,
            ribston_uri: load_env("http://pektin-ribston:80", "RIBSTON_URI", false)?,
            vault_password: load_env("", "V_PEKTIN_API_PASSWORD", true)?,
            use_policies: load_env("ribston", "USE_POLICIES", false)?,
            skip_auth: load_env("false", "SKIP_AUTH", false)?,
        })
    }
}

fn json_error_handler(err: JsonPayloadError, _: &HttpRequest) -> actix_web::error::Error {
    let err_msg = match err {
        JsonPayloadError::ContentType => "Content type error: must be 'application/json'".into(),
        _ => err.to_string(),
    };
    let err_content = json!(response_with_data(
        ResponseType::Error,
        err_msg,
        json!(null),
    ));
    ErrorBadRequest(serde_json::to_string_pretty(&err_content).expect("Could not serialize error"))
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    println!("Loading config...");
    let config = Config::from_env().context("Failed to load config")?;
    println!("Config loaded successfully.\n");

    // the redis pool needs to be created in the HttpServer::new closure because of trait bounds.
    // in there, we cannot use the ? operator. to notify the user about a potentially invalid redis
    // uri in a nice way (i.e. not via .expect()), we create a client here that checks the uri
    let redis_connection_info = if let Ok(client) = Client::open(format!(
        "redis://{}:{}@{}:{}",
        config.redis_username, config.redis_password, config.redis_hostname, config.redis_port
    )) {
        client.get_connection_info().clone()
    } else {
        bail!("Invalid redis URI")
    };
    let redis_pool_conf = deadpool_redis::Config {
        url: None,
        connection: Some(redis_connection_info.into()),
        pool: None,
    };

    let bind_addr = format!("{}:{}", &config.bind_address, &config.bind_port);

    HttpServer::new(move || {
        let redis_pool = redis_pool_conf
            .create_pool()
            .expect("Failed to create redis connection pool");
        let state = AppState {
            redis_pool,
            vault_uri: config.vault_uri.clone(),
            ribston_uri: config.ribston_uri.clone(),
            vault_password: config.vault_password.clone(),
            skip_auth: config.skip_auth.clone(),
        };
        App::new()
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allowed_header("content-type")
                    .allowed_methods(vec!["POST"])
                    .max_age(86400),
            )
            .app_data(
                web::JsonConfig::default()
                    .error_handler(json_error_handler)
                    .content_type(|mime| mime == mime::APPLICATION_JSON),
            )
            .app_data(web::Data::new(state))
            .service(get)
            .service(get_zone_records)
            .service(set)
            .service(delete)
            .service(search)
            .service(rotate)
            .service(health)
    })
    .bind(bind_addr)?
    .run()
    .await
    .map_err(|e| e.into())
}

#[post("/get")]
async fn get(
    req: web::HttpRequest,
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

async fn get_or_mget_records(
    keys: &[String],
    con: &mut Connection,
) -> Result<Vec<Option<RedisEntry>>, String> {
    // if only one key comes back in the response, redis returns an error because it cannot parse the reponse as a vector,
    // and there were also issues with a "too many arguments for a GET command" error. we therefore roll our own implementation
    // using only low-level commands.
    if keys.len() == 1 {
        match deadpool_redis::redis::cmd("GET")
            .arg(&keys[0])
            .query_async::<_, String>(con)
            .await
        {
            Ok(s) => match RedisEntry::deserialize_from_redis(&keys[0], &s) {
                Ok(data) => Ok(vec![Some(data)]),
                Err(e) => Err(e.to_string()),
            },
            Err(_) => Ok(vec![None]),
        }
    } else {
        match deadpool_redis::redis::cmd("MGET")
            .arg(&keys)
            .query_async::<_, Vec<Value>>(con)
            .await
        {
            Ok(v) => {
                let parsed_opt: Result<Vec<_>, _> = keys
                    .iter()
                    .zip(v.into_iter())
                    .map(|(key, val)| {
                        if val == Value::Nil {
                            Ok(None)
                        } else {
                            RedisEntry::deserialize_from_redis(
                                key,
                                &String::from_redis_value(&val)
                                    .expect("redis response could not be deserialized"),
                            )
                            .map(Some)
                            .map_err(|e| e.to_string())
                        }
                    })
                    .collect();
                Ok(parsed_opt?)
            }
            Err(e) => {
                let e: PektinCommonError = e.into();
                Err(e.to_string())
            }
        }
    }
}

#[post("/get-zone-records")]
async fn get_zone_records(
    req: web::HttpRequest,
    req_body: web::Json<GetZoneRecordsRequestBody>,
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
        if req_body.names.is_empty() {
            return success_with_toplevel_data("got records", json!([]));
        }

        let mut con = match state.redis_pool.get().await {
            Ok(c) => c,
            Err(_) => return internal_err("No redis connection."),
        };

        // store if a name was invalid or not absolute so we can it report back in the response.
        // we can also use the status to skip checking whether it is one of the available zones
        // if the status is not Ok
        #[derive(PartialEq)]
        enum NameStatus {
            NotAbsolute,
            Ok,
        }
        let name_status: Vec<_> = req_body
            .names
            .iter()
            .map(|name| {
                if name.is_fqdn() {
                    NameStatus::Ok
                } else {
                    NameStatus::NotAbsolute
                }
            })
            .collect();

        let names: Vec<_> = req_body.names.iter().collect();
        let zones_record_keys = match get_zone_keys(&names, &mut con).await {
            Ok(z) => z,
            Err(e) => return internal_err(e.to_string()),
        };

        // actually get the record contents, we currently only have the keys
        let mut records = Vec::with_capacity(zones_record_keys.len());
        let mut internal_error = None;
        for (idx, keys_opt) in zones_record_keys.iter().enumerate() {
            if let Some(keys) = keys_opt {
                let get_res = get_or_mget_records(keys, &mut con).await;
                if let Err(ref err) = get_res {
                    internal_error = Some(err.clone());
                }
                records.push(get_res);
            } else if name_status[idx] == NameStatus::NotAbsolute {
                records.push(Err("non-absolute name".into()));
            } else {
                records.push(Err("not found".into()));
            }
        }

        if let Some(err) = internal_error {
            internal_err(err)
        } else {
            let messages: Vec<_> = records
                .into_iter()
                .map(|records_res| match records_res {
                    Err(e) => (ResponseType::Error, e, None),
                    Ok(records) => (ResponseType::Success, "got records".into(), Some(records)),
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
                ResponseType::PartialSuccess => "couldn't get records for all zones",
                ResponseType::Error => "couldn't get records",
                ResponseType::Ignored => unreachable!(),
            };
            partial_success_with_data(toplevel_response_type, toplevel_message, messages)
        }
    } else {
        auth.message.push('\n');
        auth_err(auth.message)
    }
}

/// Takes a list of zone names and gets all records of all zones, respectively, if a zone with the
/// given name exists. Also takes care of properly separating overlapping zones (e.g. records from
/// the a.example.com. zone don't appear in the example.com. zone).
///
/// The keys in the return value are in the same order as the zones in `names`.
async fn get_zone_keys(
    names: &[&Name],
    con: &mut Connection,
) -> PektinApiResult<Vec<Option<Vec<String>>>> {
    let available_zones = pektin_common::get_authoritative_zones(con).await?;

    // we ignore non-existing names for now and store None for them
    let mut zones_record_keys = Vec::with_capacity(names.len());
    for name in names {
        if available_zones.contains(&name.to_string()) {
            let glob = format!("*{}:*", name);
            let record_keys = con
                .keys::<_, Vec<String>>(glob)
                .await
                .map_err(PektinCommonError::from)?;
            zones_record_keys.push(Some(record_keys));
        } else {
            zones_record_keys.push(None);
        }
    }

    // TODO filter out DNSSEC records

    // if the queries contains one or more pairs of zones where one zone is a subzone of the
    // other (e.g. we have a SOA record for both example.com. and a.example.com.), we don't
    // want the records of the child zone (e.g. a.example.com.) to appear in the parent zone's
    // records (e.g. example.com.)
    for zone1 in available_zones.iter() {
        for zone2 in available_zones.iter() {
            if zone1 == zone2 {
                continue;
            }
            let name1 = Name::from_utf8(zone1).expect("Key in redis is not a valid DNS name");
            let name2 = Name::from_utf8(zone2).expect("Key in redis is not a valid DNS name");
            // remove all records that belong to zone2 (the child) from zone1's (the parent's) list
            if name1.zone_of(&name2) {
                if let Some((zone1_idx, _)) =
                    names.iter().enumerate().find(|&(_, name)| *name == &name1)
                {
                    // this may also be none if the queried name was invalid
                    if let Some(record_keys) = zones_record_keys.get_mut(zone1_idx).unwrap() {
                        record_keys.retain(|record_key| {
                            let rec_name = record_key
                                .as_str()
                                .split_once(':')
                                .expect("Record key in redis has invalid format")
                                .0;
                            let rec_name = Name::from_utf8(rec_name)
                                .expect("Record key in redis is not a valid DNS name");
                            // keep element if...
                            !name2.zone_of(&rec_name)
                        });
                    }
                }
            }
        }
    }

    Ok(zones_record_keys)
}

#[post("/set")]
async fn set(
    req: web::HttpRequest,
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

        let soa_check = match check_soa(&req_body.records, &mut con).await {
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

#[post("/delete")]
async fn delete(
    req: web::HttpRequest,
    req_body: web::Json<DeleteRequestBody>,
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
            return success_with_toplevel_data("removed 0 records", 0);
        }

        // TODO:
        // - also delete RRSIG entries
        // - update NSEC chain
        let mut con = match state.redis_pool.get().await {
            Ok(c) => c,
            Err(_) => return internal_err("No redis connection."),
        };

        let valid: Vec<_> = req_body
            .records
            .iter()
            .map(|record| {
                if record.name.is_fqdn() {
                    Ok(())
                } else {
                    Err(RecordValidationError::NameNotAbsolute)
                }
            })
            .collect();
        if valid.iter().any(|s| s.is_err()) {
            let messages = valid
                .iter()
                .map(|res| res.as_ref().err().map(|e| e.to_string()))
                .collect();
            return err("One or more records were invalid.", messages);
        }

        let keys_to_delete: Vec<_> = req_body
            .records
            .iter()
            .map(|record| format!("{}:{:?}", record.name, record.rr_type))
            .collect();

        // we only check conditions that require communication with redis if all records are valid,
        // i.e. we skip these checks if we reject the request anyways

        // check that if we delete a SOA record we also delete all other records in that zone.
        // this stores the names of SOA records that should be deleted
        let zones_to_delete: Vec<_> = req_body
            .records
            .iter()
            .filter(|r| r.rr_type == RrType::SOA)
            .map(|r| &r.name)
            .collect();
        // now this stores all keys of the zones that should be deleted
        let zones_to_delete = match get_zone_keys(&zones_to_delete, &mut con).await {
            Ok(z) => z,
            Err(e) => return internal_err(e.to_string()),
        };
        // true if all of the zone's records are also deleted
        let complete_zone_deleted: Vec<_> = zones_to_delete
            .into_iter()
            .flatten()
            .map(|zone_keys| zone_keys.iter().all(|key| keys_to_delete.contains(key)))
            .collect();
        // soa_idx counts the index into complete_zone_deleted for the following iter()
        let mut soa_idx = 0;
        if complete_zone_deleted.iter().any(|b| !b) {
            let messages = req_body
                .records
                .iter()
                .map(|r| {
                    if r.rr_type != RrType::SOA {
                        None
                    } else {
                        let res = if complete_zone_deleted[soa_idx] {
                            None
                        } else {
                            Some("Requested to delete the zone's SOA record without also deleting all the other records in the zone.")
                        };
                        soa_idx += 1;
                        res
                    }
                }).collect();
            return err("One or more records were invalid.", messages);
        }

        match con.del::<_, u32>(&keys_to_delete).await {
            Ok(n) => success_with_toplevel_data(format!("removed {n} records"), n),
            Err(_) => internal_err("Could not delete records from database."),
        }
    } else {
        auth.message.push('\n');
        auth_err(auth.message)
    }
}

#[post("/search")]
async fn search(
    req: web::HttpRequest,
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
        // TODO
        /*
        if req_body.globs.is_empty() {
            return success_with_toplevel_data("Searched keys", json!([]));
        }
        */

        let mut con = match state.redis_pool.get().await {
            Ok(c) => c,
            Err(_) => return internal_err("No redis connection."),
        };

        // TODO make it possible to send multiple globs at once
        match con.keys::<_, Vec<String>>(&req_body.glob).await {
            Ok(keys) => success_with_toplevel_data("Searched keys", keys),
            Err(_) => internal_err("Could not search the database."),
        }
    } else {
        auth.message.push('\n');
        auth_err(auth.message)
    }
}

#[post("/rotate")]
async fn rotate() -> impl Responder {
    HttpResponse::NotImplemented().body("RE-SIGN ALL RECORDS FOR A ZONE")
}

#[post("/health")]
async fn health(
    req: web::HttpRequest,
    req_body: web::Json<HealthRequestBody>,
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
        let redis_con = state.redis_pool.get().await;
        let vault_status = pektin_api::vault::get_health(&state.vault_uri).await;
        let ribston_status = pektin_api::ribston::get_health(&state.ribston_uri).await;

        let all_ok = redis_con.is_ok() && vault_status == 200 && ribston_status == 200;

        let mut message =
            String::from("Pektin API is healthy but lonely without a good relation with");

        if redis_con.is_err() && vault_status != 200 && ribston_status != 200 {
            message = format!("{} {}", message, "Redis, Vault, and Ribston.")
        } else if redis_con.is_err() && vault_status != 200 {
            message = format!("{} {}", message, "Redis and Vault.")
        } else if redis_con.is_err() && ribston_status != 200 {
            message = format!("{} {}", message, "Redis and Ribston.")
        } else if vault_status != 200 && ribston_status != 200 {
            message = format!("{} {}", message, "Vault and Ribston.")
        } else if redis_con.is_err() {
            message = format!("{} {}", message, "Redis.")
        } else if vault_status != 200 {
            message = format!("{} {}", message, "Vault.")
        } else if ribston_status != 200 {
            message = format!("{} {}", message, "Ribston.")
        } else {
            message = String::from("Pektin API is feelin' good today.")
        };

        success_with_toplevel_data(
            message,
            json!({
                "api": true,
                "db": redis_con.is_ok(),
                "vault": vault_status,
                "ribston": ribston_status,
                "all": all_ok,
            }),
        )
    } else {
        auth.message.push('\n');
        HttpResponse::Unauthorized().body(auth.message)
    }
}

async fn auth_ok(
    req: &web::HttpRequest,
    request_body: RequestBody,
    state: &AppState,
    client_username: &str,
    confidant_password: &str,
) -> AuthAnswer {
    if "yes, I really want to disable authentication" == state.skip_auth {
        return AuthAnswer {
            success: true,
            message: "Skipped authentication because SKIP_AUTH is set".into(),
        };
    }

    let start = SystemTime::now();
    let utc_millis = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis();

    let api_method = match request_body {
        RequestBody::Get { .. } => "get",
        RequestBody::GetZone { .. } => "get-zone-records",
        RequestBody::Set { .. } => "set",
        RequestBody::Delete { .. } => "delete",
        RequestBody::Search { .. } => "search",
        RequestBody::Health => "health",
    }
    .into();

    auth(
        &state.vault_uri,
        &state.vault_password,
        &state.ribston_uri,
        client_username,
        confidant_password,
        RibstonRequestData {
            api_method,
            ip: req
                .connection_info()
                .realip_remote_addr()
                .map(|s| s.to_string()),
            user_agent: "Some user agent".into(),
            utc_millis,
            request_body,
        },
    )
    .await
}

/// Creates an error response with a message for each item in the request that the response is for.
///
/// The messages that are [`None`] will have a response type of [`ResponseType::Ignored`], all
/// others a type of [`ResponseType::Error`].
fn err(toplevel_message: impl Serialize, messages: Vec<Option<impl Serialize>>) -> HttpResponse {
    let messages: Vec<_> = messages
        .into_iter()
        .map(|msg| match msg {
            Some(m) => response(ResponseType::Error, json!(m)),
            None => response(
                ResponseType::Ignored,
                json!("ignored because another part of the request caused an error"),
            ),
        })
        .collect();
    HttpResponse::BadRequest().json(response_with_data(
        ResponseType::Error,
        toplevel_message,
        messages,
    ))
}

/// Creates an authentication error response.
fn auth_err(message: impl Serialize) -> HttpResponse {
    HttpResponse::Unauthorized().json(response_with_data(
        ResponseType::Error,
        message,
        json!(null),
    ))
}

/// Creates an internal server error response.
fn internal_err(message: impl Serialize) -> HttpResponse {
    HttpResponse::InternalServerError().json(response_with_data(
        ResponseType::Error,
        message,
        json!(null),
    ))
}

/// Creates a success response with a message for each item in the request that the response is
/// for.
fn success(toplevel_message: impl Serialize, messages: Vec<impl Serialize>) -> HttpResponse {
    let messages: Vec<_> = messages
        .into_iter()
        .map(|msg| response(ResponseType::Success, msg))
        .collect();
    HttpResponse::Ok().json(response_with_data(
        ResponseType::Success,
        toplevel_message,
        messages,
    ))
}

/// Creates a (partial) success response with a custom response type, message, and data for each
/// item in the request that the response is for.
fn partial_success_with_data(
    toplevel_response_type: ResponseType,
    toplevel_message: impl Serialize,
    response_type_and_messages_and_data: Vec<(ResponseType, impl Serialize, impl Serialize)>,
) -> HttpResponse {
    let messages: Vec<_> = response_type_and_messages_and_data
        .into_iter()
        .map(|(rtype, msg, data)| response_with_data(rtype, msg, data))
        .collect();
    HttpResponse::Ok().json(response_with_data(
        toplevel_response_type,
        toplevel_message,
        messages,
    ))
}

/// Creates a success response containig only a toplevel message and data value.
fn success_with_toplevel_data(message: impl Serialize, data: impl Serialize) -> HttpResponse {
    HttpResponse::Ok().json(response_with_data(ResponseType::Success, message, data))
}
