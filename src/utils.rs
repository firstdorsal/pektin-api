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
