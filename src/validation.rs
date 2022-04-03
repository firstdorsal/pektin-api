use pektin_common::{
    deadpool_redis::Connection,
    get_authoritative_zones,
    proto::rr::{Name, RecordType},
    RedisEntry, RrSet,
};
use thiserror::Error;

use crate::{
    errors_and_responses::{PektinApiError, PektinApiResult},
    types::Glob,
};

#[derive(Debug, Error)]
pub enum RecordValidationError {
    #[error("The record's name has an invalid format")]
    InvalidNameFormat,
    #[error("The record's RR set is empty")]
    EmptyRrset,
    #[error("Cannot manually set RRSIG records")]
    SetRrsig,
    #[error("The record's name contains an invalid record type: '{0}'")]
    InvalidNameRecordType(String),
    #[error("The record's name contains an invalid DNS name: '{0}'")]
    InvalidDnsName(String),
    #[error("The record type of a member of the RR set and in the record's name don't match")]
    RecordTypeMismatch,
    #[error("Too many SOA records (can only set one, duh)")]
    TooManySoas,
    #[error("The record data had an invalid format: {0}")]
    InvalidDataFormat(String),
    #[error("The record's name is not absolute (i.e. the root label at the end is missing)")]
    NameNotAbsolute,
    #[error("The record contains an empty name")]
    EmptyName,
}
pub type RecordValidationResult<T> = Result<T, RecordValidationError>;

pub fn validate_records(records: &[RedisEntry]) -> Vec<RecordValidationResult<()>> {
    records.iter().map(validate_redis_entry).collect()
}

fn validate_redis_entry(redis_entry: &RedisEntry) -> RecordValidationResult<()> {
    if redis_entry.rr_set.is_empty() {
        return Err(RecordValidationError::EmptyRrset);
    }

    if redis_entry.rr_type() == RecordType::RRSIG {
        return Err(RecordValidationError::SetRrsig);
    }

    if !redis_entry.name.is_fqdn() {
        return Err(RecordValidationError::NameNotAbsolute);
    }

    if let Err(err) = redis_entry.clone().convert() {
        return Err(RecordValidationError::InvalidDataFormat(err));
    }

    let is_soa = matches!(redis_entry.rr_set, RrSet::SOA { .. });
    if is_soa && redis_entry.rr_set.len() != 1 {
        return Err(RecordValidationError::TooManySoas);
    }

    check_for_empty_names(redis_entry)
}

/// Checks that all names in CAA, CNAME, MX, NS, SOA, and SRV records are non-empty (the root label
/// counts as non-empty).
///
/// This is needed because the empty string can be successfully converted to TrustDNS's
/// [`pektin_common::proto::rr::Name`] type.
fn check_for_empty_names(redis_entry: &RedisEntry) -> RecordValidationResult<()> {
    let empty_name = Name::from_ascii("").expect("TrustDNS doesn't allow empty names anymore :)");
    // "" == "." is true, we have to work around that
    let is_empty = |name: &Name| !name.is_root() && (name == &empty_name);

    let ok = match &redis_entry.rr_set {
        RrSet::CAA { rr_set } => rr_set.iter().all(|record| !record.value.is_empty()),
        RrSet::CNAME { rr_set } => rr_set.iter().all(|record| !is_empty(&record.value)),
        RrSet::MX { rr_set } => rr_set
            .iter()
            .all(|record| !is_empty(record.value.exchange())),
        RrSet::NS { rr_set } => rr_set.iter().all(|record| !is_empty(&record.value)),
        RrSet::SOA { rr_set } => rr_set
            .iter()
            .all(|record| !is_empty(record.value.mname()) && !is_empty(record.value.rname())),
        RrSet::SRV { rr_set } => rr_set.iter().all(|record| !is_empty(record.value.target())),
        _ => true,
    };

    if ok {
        Ok(())
    } else {
        Err(RecordValidationError::EmptyName)
    }
}

/// Checks whether the redis entry to be set either contains a SOA record or is for a zone that
/// already has a SOA record. Also returns the zones for which a new SOA record is set.
///
/// This must be called after `validate_records()`, and only if validation succeeded.
pub async fn check_soa(
    entries: &[RedisEntry],
    con: &mut Connection,
) -> PektinApiResult<(Vec<PektinApiResult<()>>, Vec<Name>)> {
    let authoritative_zones = get_authoritative_zones(con).await?;
    let authoritative_zones: Vec<_> = authoritative_zones
        .into_iter()
        .map(|zone| Name::from_utf8(zone).expect("Key in redis is not a valid DNS name"))
        .collect();

    let new_authoritative_zones: Vec<_> = entries
        .iter()
        .filter_map(|entry| {
            if matches!(entry.rr_set, RrSet::SOA { .. })
                && !authoritative_zones.contains(&entry.name)
            {
                Some(entry.name.clone())
            } else {
                None
            }
        })
        .collect();

    Ok((
        entries
            .iter()
            .map(|entry| {
                check_soa_for_single_entry(entry, &authoritative_zones, &new_authoritative_zones)
            })
            .collect(),
        new_authoritative_zones,
    ))
}

fn check_soa_for_single_entry(
    entry: &RedisEntry,
    authoriative_zones: &[Name],
    new_authoriative_zones: &[Name],
) -> PektinApiResult<()> {
    // record contains SOA
    if matches!(entry.rr_set, RrSet::SOA { .. }) {
        return Ok(());
    }

    if authoriative_zones
        .iter()
        .chain(new_authoriative_zones.iter())
        .any(|auth_zone| auth_zone.zone_of(&entry.name))
    {
        Ok(())
    } else {
        Err(PektinApiError::NoSoaRecord)
    }
}

impl Glob {
    pub fn validate(&self) -> Result<(), String> {
        if self.name_glob.contains(':') {
            Err("Invalid name glob: must not contain ':'".into())
        } else if self.rr_type_glob.contains(':') {
            Err("Invalid rr type glob: must not contain ':'".into())
        } else {
            Ok(())
        }
    }

    pub fn as_redis_glob(&self) -> String {
        format!("{}:{}", self.name_glob, self.rr_type_glob)
    }
}
