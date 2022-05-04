use std::net::Ipv4Addr;
use std::str::FromStr;

use data_encoding::BASE64;
use pektin_common::proto::rr::dnssec::Algorithm::ECDSAP256SHA256;

use pektin_common::proto::rr::dnssec::rdata::SIG;
use pektin_common::{
    proto::rr::{
        dnssec::{rdata::DNSSECRData, tbs::rrset_tbs_with_sig},
        DNSClass, Name, RData, Record, RecordType,
    },
    DnskeyRecord, DnssecAlgorithm, RedisEntry, RrSet, RrsigRecord,
};

use crate::{errors_and_responses::PektinApiResult, vault};

// create a record to be signed by vault or local in base64
pub fn create_to_be_signed(name: &str, record_type: &str) -> String {
    let record = Record::from_rdata(
        Name::from_ascii(&name).unwrap(),
        3600,
        RData::A(Ipv4Addr::from_str("2.56.96.115").unwrap()),
    );
    let sig = SIG::new(
        RecordType::from_str(record_type).unwrap(),
        ECDSAP256SHA256,
        2,
        3600,
        0,
        0,
        0,
        Name::from_ascii(&name).unwrap(),
        Vec::new(),
    );
    let tbs = rrset_tbs_with_sig(
        &Name::from_ascii(&name).unwrap(),
        DNSClass::IN,
        &sig,
        &[record],
    )
    .unwrap();
    BASE64.encode(tbs.as_ref())
}

pub async fn get_dnskey_for_zone(
    zone: &Name,
    vault_endpoint: &str,
    vault_signer_token: &str,
) -> PektinApiResult<DnskeyRecord> {
    let mut dnssec_keys =
        vault::get_zone_dnssec_keys(zone, vault_endpoint, vault_signer_token).await?;
    let dnssec_key = dnssec_keys.pop().expect("Vault returned no DNSSEC keys");

    use p256::pkcs8::DecodePublicKey;

    let dnssec_key = p256::ecdsa::VerifyingKey::from_public_key_pem(&dnssec_key)
        .expect("Vault returned invalid DNSSEC key");
    let dnssec_key_bytes = dnssec_key.to_encoded_point(false);
    let dnskey = DnskeyRecord {
        zone: true,
        secure_entry_point: true,
        revoked: false,
        algorithm: DnssecAlgorithm::ECDSAP256SHA256,
        // remove leading SEC1 tag byte (0x04 for an uncompressed point)
        key: BASE64.encode(&dnssec_key_bytes.as_bytes()[1..]),
    };

    Ok(dnskey)
}

pub async fn sign_redis_entry(
    zone: &Name,
    entry: RedisEntry,
    dnskey: &DnskeyRecord,
    vault_endpoint: &str,
    vault_token: &str,
) -> PektinApiResult<RedisEntry> {
    let signer_name = zone.clone();

    // TODO think about RRSIG signature validity period
    let sig_valid_from = chrono::Utc::now();
    let sig_valid_until = sig_valid_from + chrono::Duration::days(5);

    let dnskey_record: Vec<Record> = RedisEntry {
        name: Name::root(),
        ttl: 3600,
        rr_set: RrSet::DNSKEY {
            rr_set: vec![dnskey.clone()],
        },
    }
    .try_into()
    .expect("Could not convert DNSKEY RedisEntry to trust-dns Record");
    let dnskey_record = dnskey_record.get(0).expect("Could not get DNSKEY record");
    let dnskey = match dnskey_record.data() {
        Some(RData::DNSSEC(DNSSECRData::DNSKEY(dnskey))) => dnskey,
        _ => panic!("DNSKEY record does not contain a DNSKEY"),
    };
    let key_tag = dnskey
        .calculate_key_tag()
        .expect("Could not calculate key tag");

    let sig = SIG::new(
        entry.rr_type(),
        ECDSAP256SHA256,
        zone.num_labels(),
        entry.ttl,
        sig_valid_until.timestamp() as _,
        sig_valid_from.timestamp() as _,
        key_tag,
        signer_name.clone(),
        vec![],
    );

    let entry_owner = entry.name.clone();
    let records_tbs: Vec<Record> = entry.try_into().unwrap();
    let tbs = rrset_tbs_with_sig(zone, DNSClass::IN, &sig, &records_tbs).unwrap();
    // dbg!(tbs.as_ref());
    let signature = vault::sign_with_vault(&tbs, &signer_name, vault_endpoint, vault_token).await?;

    let rrsig_entry = RrsigRecord {
        type_covered: sig.type_covered(),
        algorithm: DnssecAlgorithm::ECDSAP256SHA256,
        labels: sig.num_labels(),
        original_ttl: sig.original_ttl(),
        signature_expiration: sig.sig_expiration(),
        signature_inception: sig.sig_inception(),
        key_tag: sig.key_tag(),
        signer_name: sig.signer_name().clone(),
        signature: BASE64.encode(&signature),
    };

    Ok(RedisEntry {
        name: entry_owner,
        // TODO think about RRSIG TTL
        ttl: 3600,
        rr_set: RrSet::RRSIG {
            rr_set: vec![rrsig_entry],
        },
    })
}

// create the signed record in redis
pub fn create_signed_db_record(signed: String) {}
