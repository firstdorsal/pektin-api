use rand::{distributions::Alphanumeric, thread_rng, Rng};

// creates a crypto random string
pub fn random_string() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(100)
        .map(char::from)
        .collect()
}

pub fn deabsolute(name: &str) -> &str {
    if let Some(deabsolute) = name.strip_suffix('.') {
        deabsolute
    } else {
        name
    }
}

// panics if `json` is not valid JSON
pub fn prettify_json(json: &str) -> String {
    serde_json::to_string_pretty(
        &serde_json::from_str::<serde_json::Value>(json).expect("Tried to prettify invalid JSON"),
    )
    .unwrap_or_else(|_| json.to_string())
}
