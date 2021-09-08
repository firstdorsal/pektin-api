#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use actix_web::HttpRequest;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use anyhow::Context;
use redis::{Client, Commands, Connection};
use std::error::Error;
use std::ops::Deref;
use std::process::exit;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use dotenv::dotenv;
use parking_lot::RwLock;
use pektin::persistence::RrSet;
use pektin_api::load_env;
use pektin_api::notify_token_rotation;
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
    key: String,
}

impl Config {
    pub fn from_env() -> PektinApiResult<Self> {
        Ok(Self {
            bind_address: load_env("0.0.0.0", "BIND_ADDRESS")?,
            bind_port: load_env("8080", "BIND_PORT")?
                .parse()
                .map_err(|_| InvalidEnvVar("BIND_PORT".into()))?,
            redis_uri: load_env("redis://redis:6379", "REDIS_URI")?,
            vault_uri: load_env("http://127.0.0.1:8200", "VAULT_URI")?,
            role_id: load_env("", "VAULT_ROLE_ID")?,
            secret_id: load_env("", "VAULT_SECRET_ID")?,
            api_key_rotation_seconds: load_env("3600", "API_KEY_ROTATION_SECONDS")?
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
        match con.get::<_, String>(&req.key) {
            Err(_) => HttpResponse::Ok().json(json!({
                "error": true,
                "data": {},
                "message": "No value found for given key.",
            })),
            Ok(v) => match serde_json::from_str::<RrSet>(&v) {
                Ok(data) => HttpResponse::Ok().json(json!({
                    "error": false,
                    "data": data,
                    "message": "Success.",
                })),
                Err(e) => HttpResponse::Ok().json(json!({
                    "error": true,
                    "data": {},
                    "message": format!("Could not parse JSON from redis: {}.", e),
                })),
            },
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[post("/set")]
async fn set() -> impl Responder {
    HttpResponse::Ok().body("SET A RECORD IN REDIS")
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
