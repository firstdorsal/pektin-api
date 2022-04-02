use pektin_common::load_env;

use crate::errors_and_responses::PektinApiResult;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub bind_address: String,
    pub bind_port: u16,
    pub redis_hostname: String,
    pub redis_username: String,
    pub redis_password: String,
    pub redis_port: u16,
    pub vault_uri: String,
    pub ribston_uri: String,
    pub vault_password: String,
    pub skip_auth: String,
    pub use_policies: String,
}

impl Config {
    pub fn from_env() -> PektinApiResult<Self> {
        Ok(Self {
            bind_address: load_env("::", "BIND_ADDRESS", false)?,
            bind_port: load_env("80", "BIND_PORT", false)?
                .parse()
                .map_err(|_| pektin_common::PektinCommonError::InvalidEnvVar("BIND_PORT".into()))?,
            redis_hostname: load_env("pektin-redis", "REDIS_HOSTNAME", false)?,
            redis_port: load_env("6379", "REDIS_PORT", false)?
                .parse()
                .map_err(|_| {
                    pektin_common::PektinCommonError::InvalidEnvVar("REDIS_PORT".into())
                })?,
            redis_username: load_env("r-pektin-api", "REDIS_USERNAME", false)?,
            redis_password: load_env("", "REDIS_PASSWORD", true)?,
            vault_uri: load_env("http://pektin-vault:80", "VAULT_URI", false)?,
            ribston_uri: load_env("http://pektin-ribston:80", "RIBSTON_URI", false)?,
            vault_password: load_env("", "V_PEKTIN_API_PASSWORD", true)?,
            use_policies: load_env("ribston", "USE_POLICIES", false)?,
            skip_auth: load_env("false", "SKIP_AUTH", false)?,
        })
    }
}
