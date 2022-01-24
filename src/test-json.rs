use pektin_common::{proto::rr::Name, RedisEntry};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let full_record = r#"{ "name": "pektin.xyz.", "rr_type": "A", "rr_set": [{ "ttl": 600, "value": "2.56.96.115" }] }"#;
    let parsed_req: RedisEntry = serde_json::from_str(full_record)?;
    let redis_key = "pektin.xyz.:A";
    let redis_value = r#"[{ "ttl": 600, "value": "2.56.96.115" }]"#;

    assert_eq!(
        redis_value.split_whitespace().collect::<String>(),
        trim_entry_for_redis(&parsed_req)
    );
    assert_eq!(
        full_record,
        reconstruct_full_json_from_redis(redis_key, redis_value)
    );

    let name = Name::from_ascii("").unwrap();
    dbg!(&name);
    dbg!(name.is_fqdn());
    dbg!(name.is_root());

    Ok(())
}

fn trim_entry_for_redis(entry: &RedisEntry) -> String {
    // TODO
    let value = serde_json::to_value(entry).unwrap();
    serde_json::to_string(&value["rr_set"]).unwrap()
}

fn reconstruct_full_json_from_redis(key: &str, value: &str) -> String {
    let (name, rr_type) = key
        .split_once(":")
        .expect("Record key in redis has invalid format");
    format!(
        r#"{{ "name": "{}", "rr_type": "{}", "rr_set": {} }}"#,
        name, rr_type, value
    )
}
