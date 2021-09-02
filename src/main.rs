use std::process::exit;

use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use pektin_api::load_env;
use pektin_api::dynamic_token_rotation;
use pektin_api::get_vault_token;
use dotenv::dotenv;
use crypto::util::fixed_time_eq;

const D_BIND_ADDRESS: &'static str = "0.0.0.0";
const D_BIND_PORT: &'static str = "8080";
const D_REDIS_URI: &'static str = "redis://redis:6379";
const D_VAULT_URI: &'static str = "http://127.0.0.1:8200";
const D_USE_VAULT: bool = true;
const D_API_KEY_ROTATION_TIME_SECONDS: u16 = 3600;
const D_VAULT_ROLE_ID: &'static str = "";
const D_VAULT_SECRET_ID: &'static str = "";

// (get, search, set) token, (get, search, set, rotate) token

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    println!("Started Pektin with these globals:");
    let redis_uri = load_env(D_REDIS_URI, "REDIS_URI");
    let bind_address = load_env(D_BIND_ADDRESS, "BIND_ADDRESS"); 
    let bind_port = load_env(D_BIND_PORT, "BIND_PORT");
    let vault_uri = load_env(D_VAULT_URI, "VAULT_URI");
    let use_vault = D_USE_VAULT; //load_env(D_USE_VAULT, "USE_VAULT");
    let role_id = load_env(D_VAULT_ROLE_ID, "VAULT_ROLE_ID");
    let secret_id = load_env(D_VAULT_SECRET_ID, "VAULT_SECRET_ID");

    let mut access_tokens:[String;2]=[String::from(""),String::from("")];
    if use_vault {
        if role_id.is_empty() || secret_id.is_empty() {
            println!("");
            println!("Error: Vault is enabled but VAULT_ROLE_ID and/or VAULT_SECRET_ID is/are unset");
            exit(0);
        }
        //dynamic_token_rotation();
    };

    println!("{}",get_vault_token(vault_uri,role_id,secret_id).unwrap());

    

    #[post("/get")]
    async fn get() -> impl Responder {
        HttpResponse::Ok().body("GET VALUE FROM REDIS")
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

    HttpServer::new(|| {
        App::new()
            .service(get)
            .service(set)
            .service(search)
    })
    .bind(format!("{}:{}", bind_address, bind_port))?
    .run()
    .await
}




