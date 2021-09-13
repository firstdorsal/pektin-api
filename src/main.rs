#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use actix_web::HttpRequest;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use anyhow::Context;
use redis::{Client, Commands, Connection};
use std::error::Error;
use std::ops::{Deref, DerefMut};
use std::process::exit;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use dotenv::dotenv;
use parking_lot::RwLock;
use pektin::persistence::RedisValue;
use pektin_api::PektinApiError::*;
use pektin_api::*;
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
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
struct GetRequest {
    token: String,
    query: String,
}

#[derive(Deserialize, Debug, Clone)]
struct SetRequest {
    token: String,
    records: Vec<RedisEntry>,
}

impl Config {
    pub fn from_env() -> PektinApiResult<Self> {
        Ok(Self {
            bind_address: load_env("0.0.0.0", "BIND_ADDRESS")?,
            bind_port: load_env("80", "BIND_PORT")?
                .parse()
                .map_err(|_| InvalidEnvVar("BIND_PORT".into()))?,
            redis_uri: load_env("redis://pektin-redis:6379", "REDIS_URI")?,
            vault_uri: load_env("http://pektin-vault:8200", "VAULT_URI")?,
            role_id: load_env("", "V_PEKTIN_API_ROLE_ID")?,
            secret_id: load_env("", "V_PEKTIN_API_SECRET_ID")?,
            api_key_rotation_seconds: load_env("21600", "API_KEY_ROTATION_SECONDS")?
                .parse()
                .map_err(|_| InvalidEnvVar("API_KEY_ROTATION_SECONDS".into()))?,
        })
    }
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
    // TODO: configure actix to either send error messages that describe why JSON could not be parsed or not to parse it at all
    HttpServer::new(move || {
        let state = AppState {
            redis_con: RwLock::new(client.get_connection().unwrap()),
            tokens: access_tokens.clone(),
        };
        App::new()
            .data(state)
            .service(get)
            .service(set)
            .service(search)
            .service(rotate)
    })
    .bind(format!("{}:{}", &config.bind_address, &config.bind_port))?
    .run()
    .await
    .map_err(|e| e.into())
}

#[post("/get")]
async fn get(req: web::Json<GetRequest>, state: web::Data<AppState>) -> impl Responder {
    // dbg!(&req);
    let tokens = state.tokens.read();
    let auth_ok =
        auth("gss", tokens.deref(), &req.token) || auth("gssr", tokens.deref(), &req.token);
    if auth_ok {
        let mut con = state.redis_con.write();
        match con.get::<_, String>(&req.query) {
            Err(_) => HttpResponse::Ok().json(json!({
                "error": true,
                "data": {},
                "message": "No value found for given key.",
            })),
            Ok(v) => match serde_json::from_str::<RedisValue>(&v) {
                Ok(data) => HttpResponse::Ok().json(json!({
                    "error": false,
                    "data": data,
                    "message": "Success.",
                })),
                Err(e) => HttpResponse::Ok().json(json!({
                    "error": true,
                    "data": {},
                    "message": format!("Could not parse JSON from database: {}.", e),
                })),
            },
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[post("/set")]
async fn set(req: web::Json<SetRequest>, state: web::Data<AppState>) -> impl Responder {
    // dbg!(&req);
    let tokens = state.tokens.read();
    let auth_ok =
        auth("gss", tokens.deref(), &req.token) || auth("gssr", tokens.deref(), &req.token);
    if auth_ok {
        let mut con = state.redis_con.write();

        let valid = validate_records(&req.records);
        if !valid.iter().all(|v| *v) {
            let invalid_indices: Vec<_> = valid
                .iter()
                .enumerate()
                .filter(|(i, v)| !*v)
                .map(|(i, v)| i)
                .collect();
            return HttpResponse::Ok().json(json!({
                "error": true,
                "data": invalid_indices,
                "message": "One or more records were invalid. Please pay more attention next time.",
            }));
        }

        if let Err(error) = check_soa(&req.records, con.deref_mut()) {
            return HttpResponse::Ok().json(json!({
                "error": true,
                "data": {},
                "message": error,
            }));
        }

        // TODO:
        // - where do we store the config whether DNSSEC is enabled?
        // - sign all records and store the RRSIGs in redis
        // - re-generate and re-sign NSEC records

        let entries: Vec<_> = req
            .records
            .iter()
            .map(|e| (&e.name, serde_json::to_string(&e.value).unwrap()))
            .collect();
        // TODO change this to `con.set_multiple(&entries)` and test
        match redis::pipe().set_multiple(&entries).query(con.deref_mut()) {
            Ok(()) => HttpResponse::Ok().json(json!({
                "error": false,
                "data": {},
                "message": "Success.",
            })),
            Err(_) => HttpResponse::Ok().json(json!({
                "error": true,
                "data": {},
                "message": "Could not set records in database.",
            })),
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[post("/search")]
async fn search() -> impl Responder {
    HttpResponse::Ok().body("GET ALL VALUES CONTAINING FROM REDIS")
}

#[post("/rotate")]
async fn rotate() -> impl Responder {
    HttpResponse::Ok().body("RE-SIGN ALL RECORDS FOR A ZONE")
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
