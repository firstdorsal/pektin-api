use pektin_common::proto::rr::Name;
use pektin_common::{Property, RecordData};
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn Error>> {
    let a = RecordData::A(Ipv4Addr::from_str("2.56.96.115").unwrap());
    let aaaa = RecordData::AAAA(Ipv6Addr::from_str("2a03:4000:3e:dd::1").unwrap());
    let caa = RecordData::CAA {
        issuer_critical: true,
        tag: Property::Issue,
        value: "letsencrypt.org".into(),
    };
    let cname = RecordData::CNAME(Name::from_ascii("vonforell.de.").unwrap());
    // let mx = RecordData::MX()

    println!("{}", serde_json::to_string_pretty(&a)?);
    println!("{}", serde_json::to_string_pretty(&aaaa)?);
    println!("{}", serde_json::to_string_pretty(&caa)?);
    println!("{}", serde_json::to_string_pretty(&cname)?);

    Ok(())
}
