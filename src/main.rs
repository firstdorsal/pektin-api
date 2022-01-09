use actix_cors::Cors;
use actix_web::error::{ErrorBadRequest, JsonPayloadError};
use actix_web::{post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use anyhow::{bail, Context};
use dotenv::dotenv;
use parking_lot::RwLock;
use pektin_api::*;
use pektin_common::deadpool_redis::redis::{AsyncCommands, Client, FromRedisValue, Value};
use pektin_common::deadpool_redis::{self, Pool};
use pektin_common::proto::rr::Name;
use pektin_common::{load_env, RedisEntry};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    pub bind_address: String,
    pub bind_port: u16,
    pub redis_uri: String,
    pub vault_uri: String,
    pub ribston_uri: String,
    pub vault_password: String,
}

struct AppState {
    redis_pool: Pool,
    tokens: Arc<RwLock<PektinApiTokens>>,
    vault_uri: String,
    ribston_uri: String,
}

impl Config {
    pub fn from_env() -> PektinApiResult<Self> {
        Ok(Self {
            bind_address: load_env("::", "BIND_ADDRESS", false)?,
            bind_port: load_env("80", "BIND_PORT", false)?
                .parse()
                .map_err(|_| pektin_common::PektinCommonError::InvalidEnvVar("BIND_PORT".into()))?,
            redis_uri: load_env("redis://pektin-redis:6379", "REDIS_URI", false)?,
            vault_uri: load_env("http://pektin-vault:8200", "VAULT_URI", false)?,
            ribston_uri: load_env("http://127.0.0.1:8888", "RIBSTON_URI", false)?,
            vault_password: load_env("", "V_PEKTIN_API_PASSWORD", true)?,
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

    let access_tokens = Arc::new(RwLock::new(Default::default()));

    // the redis pool needs to be created in the HttpServer::new closure because of trait bounds.
    // in there, we cannot use the ? operator. to notify the user about a potentially invalid redis
    // uri in a nice way (i.e. not via .expect()), we create a client here that checks the uri
    let redis_connection_info = if let Ok(client) = Client::open(config.redis_uri.clone()) {
        client.get_connection_info().clone()
    } else {
        bail!("Invalid redis URI")
    };
    let redis_pool_conf = deadpool_redis::Config {
        url: None,
        connection: Some(redis_connection_info.into()),
        pool: None,
    };
    let vault_uri = config.vault_uri.clone();
    let ribston_uri = config.ribston_uri.clone();

    HttpServer::new(move || {
        let redis_pool = redis_pool_conf
            .create_pool()
            .expect("Failed to create redis connection pool");
        let state = AppState {
            redis_pool,
            tokens: access_tokens.clone(),
            vault_uri: vault_uri.clone(),
            ribston_uri: ribston_uri.clone(),
        };
        App::new()
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allowed_header("content-type")
                    .allowed_methods(vec!["POST"]),
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
    .bind(format!("{}:{}", &config.bind_address, &config.bind_port))?
    .run()
    .await
    .map_err(|e| e.into())
}

#[post("/get")]
async fn get(req_body: web::Json<GetRequestBody>, state: web::Data<AppState>) -> impl Responder {
    if auth_ok(&req_body.token, state.deref()) {
        let mut con = match state.redis_pool.get().await {
            Ok(c) => c,
            Err(_) => return err("No redis connection."),
        };
        // if only one key comes back in the response, redis returns an error because it cannot parse the reponse as a vector,
        // and there were also issues with a "too many arguments for a GET command" error. we therefore roll our own implementation
        // using only low-level commands.
        if req_body.keys.len() == 1 {
            match deadpool_redis::redis::cmd("GET")
                .arg(&req_body.keys[0])
                .query_async::<_, String>(&mut con)
                .await
            {
                Ok(s) => match serde_json::from_str::<RedisEntry>(&s) {
                    Ok(data) => success(vec![data]),
                    Err(e) => err(format!("Could not parse JSON from database: {}.", e)),
                },
                Err(_) => err("No value found for given key."),
            }
        } else {
            match deadpool_redis::redis::cmd("MGET")
                .arg(&req_body.keys)
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
                    success(parsed_opt)
                }
                Err(_) => err("No value found for given key."),
            }
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[post("/get-zone-records")]
async fn get_zone_records(
    req_body: web::Json<GetZoneRecordsRequestBody>,
    state: web::Data<AppState>,
) -> impl Responder {
    if auth_ok(&req_body.token, state.deref()) {
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
        let invalid_names: Vec<_> = queried_names
            .iter()
            .filter(|n| !available_zones.contains(n))
            .collect();
        if !invalid_names.is_empty() {
            return err_with_data("One or more names do not exist.", invalid_names);
        }

        let mut zones_record_keys = HashMap::new();
        for name in &queried_names {
            let glob = format!("*{}:*", name);
            match con.keys::<_, Vec<String>>(glob).await {
                Ok(record_keys) => zones_record_keys.insert(name, record_keys),
                Err(e) => return err(e.to_string()),
            };
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

        // TODO actually get the record contents, we currently only have the keys?
        success(zones_record_keys)
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[post("/set")]
async fn set(
    req: HttpRequest,
    req_body: web::Json<SetRequestBody>,
    state: web::Data<AppState>,
) -> impl Responder {
    let start = SystemTime::now();
    let time_now_millis = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis();

    let answer = ribston::evaluate(
        &state.ribston_uri,
        String::from(include_str!("./old/policy.ts")),
        ribston::RibstonRequestData {
            ip: req
                .connection_info()
                .realip_remote_addr()
                .map(|s| s.to_string()),
            utc_millis: time_now_millis,
            api_method: String::from("set"),
            user_agent: String::from("some user agent"),
            redis_entries: req_body.records.clone(),
        },
    )
    .await;
    println!("{:?}", answer);

    if auth_ok(&req_body.token, state.deref()) {
        let mut con = match state.redis_pool.get().await {
            Ok(c) => c,
            Err(_) => return err("No redis connection."),
        };

        let valid = validate_records(&req_body.records);
        if valid.iter().any(|v| v.is_err()) {
            let invalid_indices: Vec<_> = valid
                .iter()
                .enumerate()
                .filter(|(_, v)| v.is_err())
                .map(|(i, err)| json!({i.to_string(): err.as_ref().err().unwrap().to_string()}))
                .collect();
            return HttpResponse::Ok().json(json!({
                "error": true,
                "data": invalid_indices,
                "message": "One or more records were invalid. Please pay more attention next time.",
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
        HttpResponse::Unauthorized().finish()
    }
}

#[post("/delete")]
async fn delete(
    req_body: web::Json<DeleteRequestBody>,
    state: web::Data<AppState>,
) -> impl Responder {
    if auth_ok(&req_body.token, state.deref()) {
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
        HttpResponse::Unauthorized().finish()
    }
}

#[post("/search")]
async fn search(
    req_body: web::Json<SearchRequestBody>,
    state: web::Data<AppState>,
) -> impl Responder {
    if auth_ok(&req_body.token, state.deref()) {
        let mut con = match state.redis_pool.get().await {
            Ok(c) => c,
            Err(e) => return err(format!("No redis connection: {}.", e)),
        };

        match con.keys::<_, Vec<String>>(&req_body.glob).await {
            Ok(keys) => success(keys),
            Err(_) => err("Could not search the database."),
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[post("/rotate")]
async fn rotate() -> impl Responder {
    HttpResponse::NotImplemented().body("RE-SIGN ALL RECORDS FOR A ZONE")
}

#[post("/sys/health")]
async fn health(
    req: web::HttpRequest,
    req_body: web::Json<HealthRequestBody>,
    state: web::Data<AppState>,
) -> impl Responder {
    /*
        println!(
            "Address {:?}, Headers: {:?}",
            req.connection_info().realip_remote_addr(),
            req.headers()
        );
        // curl -X 'POST' http://[::]:8099/sys/health -v -H 'content-type: application/json' -d '{"token":""}'
    */
    if auth_ok(&req_body.token, state.deref()) {
        let redis_con = state.redis_pool.get().await;
        let vault_status = pektin_api::vault::get_health(state.vault_uri.clone()).await;
        let ribston_status = pektin_api::ribston::get_health(state.ribston_uri.clone()).await;

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
        HttpResponse::Unauthorized().finish()
    }
}

fn auth_ok(token: &str, state: &AppState) -> bool {
    if let Ok(var) = env::var("DISABLE_AUTH") {
        if var == "yes, I really want to disable authentication" {
            return true;
        }
    }

    auth()
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
