use actix_cors::Cors;
use actix_web::error::{ErrorBadRequest, JsonPayloadError};
use actix_web::{post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use anyhow::Context;
use redis::{Client, Commands, Connection};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use dotenv::dotenv;
use parking_lot::RwLock;
use pektin_api::*;
use pektin_common::{load_env, RedisEntry, RedisValue};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    pub bind_address: String,
    pub bind_port: u16,
    pub redis_uri: String,
    pub vault_uri: String,
    pub role_id: String,
    pub secret_id: String,
    pub api_key_rotation_seconds: u64,
}

struct AppState {
    redis_con: RwLock<Connection>,
    tokens: Arc<RwLock<PektinApiTokens>>,
}

#[derive(Deserialize, Debug, Clone)]
struct GetRequestBody {
    token: String,
    queries: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
struct SetRequestBody {
    token: String,
    records: Vec<RedisEntry>,
}

#[derive(Deserialize, Debug, Clone)]
struct DeleteRequestBody {
    token: String,
    keys: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
struct SearchRequestBody {
    token: String,
    glob: String,
}

impl Config {
    pub fn from_env() -> PektinApiResult<Self> {
        Ok(Self {
            bind_address: load_env("0.0.0.0", "BIND_ADDRESS")?,
            bind_port: load_env("80", "BIND_PORT")?
                .parse()
                .map_err(|_| pektin_common::PektinCommonError::InvalidEnvVar("BIND_PORT".into()))?,
            redis_uri: load_env("redis://pektin-redis:6379", "REDIS_URI")?,
            vault_uri: load_env("http://pektin-vault:8200", "VAULT_URI")?,
            role_id: load_env("", "V_PEKTIN_API_ROLE_ID")?,
            secret_id: load_env("", "V_PEKTIN_API_SECRET_ID")?,
            api_key_rotation_seconds: load_env("21600", "API_KEY_ROTATION_SECONDS")?
                .parse()
                .map_err(|_| {
                    pektin_common::PektinCommonError::InvalidEnvVar(
                        "API_KEY_ROTATION_SECONDS".into(),
                    )
                })?,
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

    let client = Client::open(config.redis_uri.clone())?;

    {
        let tokens_clone = access_tokens.clone();
        let config_clone = config.clone();
        let seconds_clone = config.api_key_rotation_seconds;
        thread::spawn(move || schedule_token_rotation(tokens_clone, config_clone, seconds_clone));
    }

    let _ = client
        .get_connection()
        .context("could not connect to redis")?;

    HttpServer::new(move || {
        let state = AppState {
            redis_con: RwLock::new(client.get_connection().unwrap()),
            tokens: access_tokens.clone(),
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
            .data(state)
            .service(get)
            .service(set)
            .service(delete)
            .service(search)
            .service(rotate)
    })
    .bind(format!("{}:{}", &config.bind_address, &config.bind_port))?
    .run()
    .await
    .map_err(|e| e.into())
}

#[post("/get")]
async fn get(req: web::Json<GetRequestBody>, state: web::Data<AppState>) -> impl Responder {
    if auth_ok(&req.token, state.deref()) {
        let mut con = state.redis_con.write();
        // if only one key comes back in the response, redis returns an error because it cannot parse the reponse as a vector,
        // and there were also issues with a "too many arguments for a GET command" error. we therefore roll our own implementation
        // using only low-level commands.
        if req.queries.len() == 1 {
            match redis::cmd("GET")
                .arg(&req.queries[0])
                .query::<String>(con.deref_mut())
            {
                Ok(s) => match serde_json::from_str::<RedisValue>(&s) {
                    Ok(data) => success(data),
                    Err(e) => err(format!("Could not parse JSON from database: {}.", e)),
                },
                Err(e) => err(format!("No value found for given key: {}.", e)),
            }
        } else {
            match redis::cmd("MGET")
                .arg(&req.queries)
                .query::<Vec<String>>(con.deref_mut())
            {
                Ok(v) => {
                    let parsed_opt: Result<Vec<_>, _> = v
                        .into_iter()
                        .map(|s| serde_json::from_str::<RedisValue>(&s))
                        .collect();
                    match parsed_opt {
                        Ok(data) => success(data),
                        Err(e) => err(format!("Could not parse JSON from database: {}.", e)),
                    }
                }
                Err(e) => err(format!("No value found for given key: {}.", e)),
            }
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[post("/set")]
async fn set(req: web::Json<SetRequestBody>, state: web::Data<AppState>) -> impl Responder {
    if auth_ok(&req.token, state.deref()) {
        let mut con = state.redis_con.write();

        let valid = validate_records(&req.records);
        if !valid.iter().all(|v| *v) {
            let invalid_indices: Vec<_> = valid
                .iter()
                .enumerate()
                .filter(|(_, v)| !*v)
                .map(|(i, _)| i)
                .collect();
            return HttpResponse::Ok().json(json!({
                "error": true,
                "data": invalid_indices,
                "message": "One or more records were invalid. Please pay more attention next time.",
            }));
        }

        if let Err(error) = check_soa(&req.records, con.deref_mut()) {
            return err(error);
        }

        // TODO:
        // - where do we store the config whether DNSSEC is enabled? -> DNSSEC is always enabled
        // - sign all records and store the RRSIGs in redis
        // - re-generate and re-sign NSEC records

        let entries: Vec<_> = req
            .records
            .iter()
            .map(|e| (&e.name, serde_json::to_string(&e.value).unwrap()))
            .collect();
        // TODO change this to `con.set_multiple(&entries)` and test
        match redis::pipe().set_multiple(&entries).query(con.deref_mut()) {
            Ok(()) => success(json!({})),
            Err(_) => err("Could not set records in database."),
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[post("/delete")]
async fn delete(req: web::Json<DeleteRequestBody>, state: web::Data<AppState>) -> impl Responder {
    if auth_ok(&req.token, state.deref()) {
        // TODO:
        // - also delete RRSIG entries
        // - update NSEC chain
        let mut con = state.redis_con.write();
        match con.del::<_, u32>(&req.keys) {
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
async fn search(req: web::Json<SearchRequestBody>, state: web::Data<AppState>) -> impl Responder {
    if auth_ok(&req.token, state.deref()) {
        let mut con = state.redis_con.write();
        match con.keys::<_, Vec<String>>(&req.glob) {
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

fn schedule_token_rotation(
    tokens: Arc<RwLock<PektinApiTokens>>,
    config: Config,
    sleep_seconds: u64,
) {
    loop {
        {
            let gss_token = format!("gss_token:{}", random_string());
            let gssr_token = format!("gssr_token:{}", random_string());
            dbg!("{}\n{}", &gss_token, &gssr_token);
            let notify = notify_token_rotation(
                &gss_token,
                &gssr_token,
                &config.vault_uri,
                &config.role_id,
                &config.secret_id,
            );
            if notify.is_err() {
                println!("Notifying vault failed: {:?}", notify);
                println!("");
            }
            let mut tokens_write = tokens.write();
            tokens_write.gss_token = gss_token;
            tokens_write.gssr_token = gssr_token;
        }
        thread::sleep(Duration::from_secs(sleep_seconds));
    }
}

fn auth_ok(token: &str, state: &AppState) -> bool {
    let tokens = state.tokens.read();
    auth("gss", tokens.deref(), token) || auth("gssr", tokens.deref(), token)
}

fn err(msg: impl Serialize) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "error": true,
        "data": {},
        "message": msg,
    }))
}

fn success(data: impl Serialize) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "error": false,
        "data": data,
        "message": "Success.",
    }))
}
