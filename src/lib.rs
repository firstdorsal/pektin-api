use std::env;

use std::time::Duration;
use std::thread;

use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

use trust_dns_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_proto::rr::dnssec::tbs::*;
use trust_dns_proto::rr::dnssec::rdata::*;
use trust_dns_proto::rr::dnssec::Algorithm::ECDSAP256SHA256;
use std::net::{Ipv4Addr};
use std::str::FromStr;
use base64::{encode,decode};

use reqwest;
use serde_json::json;
use serde::Deserialize;


//use serde::Deserialize;

pub fn load_env(default_parameter: &str, parameter_name: &str) -> String {
    let mut p = String::from(default_parameter);
    if let Ok(param) = env::var(parameter_name) {
        if param.len() > 0 {
            p = param;
        }
    };
    println!("{}: {}", parameter_name, p);
    return p;
}

// rotate token on vault
pub fn dynamic_token_rotation(){
    println!("Periodic task!");
    thread::sleep(Duration::from_secs(3600));
    dynamic_token_rotation();
}

// creates a crypto random string for use as token
fn random_string()-> String{
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(100)
        .map(char::from)
        .collect()
}

// create a record to be signed by vault or local in base64
fn create_to_be_signed(name: String, record_type: String) -> String {
    let record = Record::from_rdata(
        Name::from_ascii(&name).unwrap(), 
        3600, 
        RData::A(Ipv4Addr::from_str("2.56.96.115").unwrap())
    );
    let sig=SIG::new(
        RecordType::from_str(&record_type).unwrap(),
        ECDSAP256SHA256,
        2, 3600, 0, 0, 0,
        Name::from_ascii(&name).unwrap(),
        Vec::new()
    );
    let tbs=rrset_tbs_with_sig(&Name::from_ascii(&name).unwrap(), DNSClass::IN, &sig, &[record]).unwrap();
    return encode(tbs);
}


// takes a base64 record and signs it with vault
fn sign_with_vault(tbs:String, domain: String){

}

fn create_key(domain: String){

}



// get the vault access token with role and secret id
pub fn get_vault_token(vault_uri: String, role_id: String, secret_id: String)-> Result<String, Box<dyn std::error::Error>>{
    let res: String = reqwest::blocking::Client::new()
        .post(format!("{}{}",vault_uri,"/v1/auth/approle/login"))
        .json(&json!({
            "role_id": role_id,
            "secret_id": secret_id
        }))
        .send()?
        .text()
        .unwrap();
    #[derive(Deserialize, Debug)]
    struct VaultRes {
        auth: VaultAuth,
    }
    #[derive(Deserialize, Debug)]
    struct VaultAuth{
        client_token: String,
    }
    let vault_res=serde_json::from_str::<VaultRes>(&res).unwrap();
    Ok(vault_res.auth.client_token)
}

// create the signed record in redis
fn create_db_record(signed: String){

}