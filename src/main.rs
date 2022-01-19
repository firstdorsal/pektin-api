use actix_cors::Cors;
use actix_web::error::{ErrorBadRequest, JsonPayloadError};
use actix_web::{post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use anyhow::{bail, Context};
use dotenv::dotenv;
use pektin_api::ribston::RibstonRequestData;
use pektin_api::*;
use pektin_common::deadpool_redis::redis::{AsyncCommands, Client, FromRedisValue, Value};
use pektin_common::deadpool_redis::{self, Pool};
use pektin_common::proto::rr::Name;
use pektin_common::{load_env, PektinCommonError, RedisEntry};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
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
            vault_uri: load_env("http://pektin-vault:8200", "VAULT_URI", false)?,
            ribston_uri: load_env("http://pektin-ribston:80", "RIBSTON_URI", false)?,
            vault_password: load_env("", "V_PEKTIN_API_PASSWORD", true)?,
            skip_auth: load_env("false", "SKIP_AUTH", false)?,
        })
    }
}

fn json_error_handler(err: JsonPayloadError, _: &HttpRequest) -> actix_web::error::Error {
    let err_msg = match err {
        JsonPayloadError::ContentType => "Content type error: must be 'application/json'".into(),
        _ => err.to_string(),
    };
    ErrorBadRequest(err_msg)
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
        // TODO
        match get_or_mget_records(&req_body.keys, &state.redis_pool).await {
            Ok(records) => success(records),
            Err(e) => err(e),
        }
    } else {
        auth.message.push('\n');
        HttpResponse::Unauthorized().body(auth.message)
    }
}

async fn get_or_mget_records(
    keys: &[String],
    redis_pool: &Pool,
) -> Result<Vec<Option<RedisEntry>>, String> {
    let mut con = match redis_pool.get().await {
        Ok(c) => c,
        Err(_) => return Err("No redis connection.".into()),
    };
    // if only one key comes back in the response, redis returns an error because it cannot parse the reponse as a vector,
    // and there were also issues with a "too many arguments for a GET command" error. we therefore roll our own implementation
    // using only low-level commands.
    if keys.len() == 1 {
        match deadpool_redis::redis::cmd("GET")
            .arg(&keys[0])
            .query_async::<_, String>(&mut con)
            .await
        {
            Ok(s) => match serde_json::from_str::<RedisEntry>(&s) {
                Ok(data) => Ok(vec![Some(data)]),
                Err(e) => Err(format!("Could not parse JSON from database: {}.", e)),
            },
            Err(_) => Ok(vec![None]),
        }
    } else {
        match deadpool_redis::redis::cmd("MGET")
            .arg(&keys)
            .query_async::<_, Vec<Value>>(&mut con)
            .await
        {
            Ok(v) => {
                let parsed_opt: Vec<_> = v
                    .into_iter()
                    .map(|val| {
                        if val == Value::Nil {
                            None
                        } else {
                            serde_json::from_str::<RedisEntry>(
                                &String::from_redis_value(&val)
                                    .expect("redis response could not be deserialized"),
                            )
                            .ok()
                        }
                    })
                    .collect();
                Ok(parsed_opt)
            }
            Err(e) => {
                let e: PektinCommonError = e.into();
                Err(e.to_string())
            }
        }
    }
}

// TODO give back consistent errors in the data field

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
        let mut con = match state.redis_pool.get().await {
            Ok(c) => c,
            Err(_) => return err("No redis connection."),
        };

        // ensure all names in req.names are absolute
        let queried_names: Vec<_> = req_body.names.iter().map(make_absolute_name).collect();

        let available_zones = match pektin_common::get_authoritative_zones(&mut con).await {
            Ok(z) => z,
            Err(e) => return err(e.to_string()),
        };

        // we ignore the invalid names for now and only store the valid ones in zones_record_keys
        // at the end of this function, we insert None back into the HashMap for the invalid names
        let mut invalid_names = Vec::with_capacity(queried_names.len());

        let mut zones_record_keys = HashMap::new();
        for name in queried_names.iter() {
            if available_zones.contains(name) {
                let glob = format!("*{}:*", name);
                match con.keys::<_, Vec<String>>(glob).await {
                    Ok(record_keys) => zones_record_keys.insert(name, record_keys),
                    Err(e) => return err(e.to_string()),
                };
            } else {
                invalid_names.push(name);
            }
        }

        // TODO filter out DNSSEC records

        let mut overlapping_zones = vec![];
        for zone1 in available_zones.iter() {
            for zone2 in available_zones.iter() {
                if zone1 == zone2 {
                    continue;
                }
                let name1 = Name::from_utf8(zone1).expect("Key in redis is not a valid DNS name");
                let name2 = Name::from_utf8(zone2).expect("Key in redis is not a valid DNS name");
                if name1.zone_of(&name2) {
                    overlapping_zones.push((zone1, zone2));
                }
            }
        }

        for (parent, child) in overlapping_zones.into_iter() {
            if !zones_record_keys.contains_key(parent) {
                continue;
            }
            zones_record_keys
                .get_mut(parent)
                .unwrap()
                .retain(|rec_name| {
                    let rec_name = rec_name.as_str().split_once(':').unwrap().0;
                    let rec_name = Name::from_utf8(rec_name)
                        .expect("Record key in redis was not a valid DNS name");
                    let child_name = Name::from_utf8(child)
                        .expect("Record key in redis was not a valid DNS name");
                    !child_name.zone_of(&rec_name)
                });
        }

        // actually get the record contents, we currently only have the keys
        let (zones, keys_per_zone): (Vec<_>, Vec<_>) = zones_record_keys.into_iter().unzip();
        let mut records = Vec::with_capacity(keys_per_zone.len());
        for keys in keys_per_zone {
            records.push(get_or_mget_records(&keys, &state.redis_pool).await);
        }
        let records: Result<Vec<_>, _> = records.into_iter().collect();
        match records {
            Err(e) => err(e),
            Ok(recs) => {
                let mut zones_records: HashMap<_, _> = zones
                    .into_iter()
                    .zip(recs.into_iter().map(|r| Some(r)))
                    .collect();
                for name in invalid_names.iter() {
                    zones_records.insert(name, None);
                }
                success(zones_records)
            }
        }
    } else {
        auth.message.push('\n');
        HttpResponse::Unauthorized().body(auth.message)
    }
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
        let mut con = match state.redis_pool.get().await {
            Ok(c) => c,
            Err(_) => return err("No redis connection."),
        };

        let valid = validate_records(&req_body.records);
        if valid.iter().any(|v| v.is_err()) {
            let invalid_indices: Vec<_> = valid
                .iter()
                .enumerate()
                .map(|(_, res)| match res {
                    Ok(()) => json!(null),
                    Err(e) => json!(e.to_string()),
                })
                .collect();
            return HttpResponse::Ok().json(json!({
                "error": true,
                "data": invalid_indices,
                "message": "One or more records were invalid.",
            }));
        }

        if let Err(error) = check_soa(&req_body.records, &mut con).await {
            return err(error.to_string());
        }

        // TODO:
        // - where do we store the config whether DNSSEC is enabled? -> DNSSEC is always enabled
        // - sign all records and store the RRSIGs in redis
        // - re-generate and re-sign NSEC records

        let entries: Vec<_> = req_body
            .records
            .iter()
            .map(|e| {
                let (name, rr_type) = e.name.split_once(":").unwrap();
                (
                    format!("{}:{}", name.to_lowercase(), rr_type),
                    serde_json::to_string(&e).unwrap(),
                )
            })
            .collect();
        match con.set_multiple(&entries).await {
            Ok(()) => success(()),
            Err(_) => err("Could not set records in database."),
        }
    } else {
        auth.message.push('\n');
        HttpResponse::Unauthorized().body(auth.message)
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
        // TODO:
        // - also delete RRSIG entries
        // - update NSEC chain
        let mut con = match state.redis_pool.get().await {
            Ok(c) => c,
            Err(_) => return err("No redis connection."),
        };

        match con.del::<_, u32>(&req_body.keys).await {
            Ok(n) if n > 0 => success(json!({ "keys_removed": n })),
            Ok(_) => HttpResponse::Ok().json(json!({
                "error": false,
                "data": {},
                "message": "No matching keys found.",
            })),
            Err(_) => err("Could not delete keys from database."),
        }
    } else {
        auth.message.push('\n');
        HttpResponse::Unauthorized().body(auth.message)
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
        let mut con = match state.redis_pool.get().await {
            Ok(c) => c,
            Err(e) => return err(format!("No redis connection: {}.", e)),
        };

        match con.keys::<_, Vec<String>>(&req_body.glob).await {
            Ok(keys) => success(keys),
            Err(_) => err("Could not search the database."),
        }
    } else {
        auth.message.push('\n');
        HttpResponse::Unauthorized().body(auth.message)
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
            message = format!("{} {}", message, "Redis, Vault, and OPA.")
        } else if redis_con.is_err() && vault_status != 200 {
            message = format!("{} {}", message, "Redis and Vault.")
        } else if redis_con.is_err() && ribston_status != 200 {
            message = format!("{} {}", message, "Redis and OPA.")
        } else if vault_status != 200 && ribston_status != 200 {
            message = format!("{} {}", message, "Vault and OPA.")
        } else if redis_con.is_err() {
            message = format!("{} {}", message, "Redis.")
        } else if vault_status != 200 {
            message = format!("{} {}", message, "Vault.")
        } else if ribston_status != 200 {
            message = format!("{} {}", message, "OPA.")
        } else {
            message = String::from("Pektin API is feelin' good today.")
        };

        HttpResponse::Ok().json(json!({
            "error": false,
            "data": {
                "api":true,
                "db": redis_con.is_ok(),
                "vault": vault_status,
                "ribston": ribston_status,
                "all": all_ok
            },
            "message":  message
        }))
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

    // TODO: different request bodys need to be handled/ converted

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

fn err_with_data(msg: impl Serialize, data: impl Serialize) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "error": true,
        "data": data,
        "message": msg,
    }))
}

fn err(msg: impl Serialize) -> HttpResponse {
    err_with_data(msg, ())
}

fn success(data: impl Serialize) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "error": false,
        "data": data,
        "message": "Success.",
    }))
}

// appends '.' at end if necessary
// also removes all whitespace
fn make_absolute_name(name: impl AsRef<str>) -> String {
    let mut name: String = name.as_ref().split_whitespace().collect();
    if !name.ends_with('.') {
        name.push('.');
    }
    name
}
