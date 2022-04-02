use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use anyhow::{bail, Context};
use dotenv::dotenv;

use pektin_api::config::Config;
use pektin_api::delete::delete;
use pektin_api::errors_and_responses::json_error_handler;
use pektin_api::get::get;
use pektin_api::get_zone_records::get_zone_records;
use pektin_api::health::health;
use pektin_api::search::search;
use pektin_api::set::set;

use pektin_api::types::AppState;
use pektin_common::deadpool_redis;
use pektin_common::deadpool_redis::redis::Client;

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
            .service(health)
    })
    .bind(bind_addr)?
    .run()
    .await
    .map_err(|e| e.into())
}
