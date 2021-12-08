use std::{
    net::Ipv6Addr,
    time::{SystemTime, UNIX_EPOCH},
};

mod opa;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_opa().await;
    Ok(())
}

pub async fn run_opa() {
    let policy = r#"
    package system.main
import future.keywords.in

default domain = false
default api_methods = false
default rr_types = false
default value = false
default ip = false
default utc_millis = false


domain {
    startswith(input.domain,"_acme-challenge.")
    endswith(input.domain,".")
}

api_methods {
    input.api_methods in ["set","get","delete"]
}

rr_types {
    input.rr_types in ["TXT"]
}

value_patterns {
    true
}


    
    
    "#;

    let start = SystemTime::now();
    let time_now_millis = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis();

    let res = opa::evaluate(
        "http://127.0.0.1:8081",
        policy,
        opa::OpaRequestData {
            domain: (String::from("_acme-challenge.y.gy.")),
            api_methods: (String::from("set")),
            rr_types: (String::from("TXT")),
            value: (String::from("kdf9j3898989r34rj890dewkio")),
            ip: (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            utc_millis: (time_now_millis),
        },
    )
    .await;
    println!("{:?}", res);
}
