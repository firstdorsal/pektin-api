use data_encoding::BASE64;
use pektin_common::proto::rr::dnssec::rdata::SIG;
use pektin_common::proto::rr::dnssec::Algorithm::ECDSAP256SHA256;
use pektin_common::proto::rr::dnssec::{rdata::DNSSECRData, tbs::rrset_tbs_with_sig};
use pektin_common::proto::rr::{DNSClass, Name, RData, Record};
use pektin_common::{DbEntry, DnskeyRecord, DnssecAlgorithm, RrSet, RrsigRecord};
use tracing::instrument;

use crate::{errors_and_responses::PektinApiResult, vault};

#[instrument(skip(vault_endpoint, vault_signer_token))]
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

#[instrument(skip(vault_endpoint, vault_token))]
pub async fn sign_db_entry(
    zone: &Name,
    entry: DbEntry,
    dnskey: &DnskeyRecord,
    vault_endpoint: &str,
    vault_token: &str,
) -> PektinApiResult<DbEntry> {
    let signer_name = zone.clone();

    // TODO think about RRSIG signature validity period
    let sig_valid_from = chrono::Utc::now();
    let sig_valid_until = sig_valid_from + chrono::Duration::days(5);

    let dnskey_record: Vec<Record> = DbEntry {
        name: Name::root(),
        ttl: 3600,
        rr_set: RrSet::DNSKEY {
            rr_set: vec![dnskey.clone()],
        },
    }
    .try_into()
    .expect("Could not convert DNSKEY DbEntry to trust-dns Record");
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

    let records_tbs: Vec<Record> = entry.clone().try_into().unwrap();
    let tbs = rrset_tbs_with_sig(zone, DNSClass::IN, &sig, &records_tbs).unwrap();
    // dbg!(tbs.as_ref());
    let signature = vault::sign_with_vault(&tbs, &signer_name, vault_endpoint, vault_token).await?;

    let rrsig_entry = RrsigRecord {
        type_covered: sig.type_covered(),
        algorithm: DnssecAlgorithm::ECDSAP256SHA256,
        labels: entry.name.num_labels(),
        original_ttl: sig.original_ttl(),
        signature_expiration: sig.sig_expiration(),
        signature_inception: sig.sig_inception(),
        key_tag: sig.key_tag(),
        signer_name: sig.signer_name().clone(),
        signature: BASE64.encode(&signature),
    };

    Ok(DbEntry {
        name: entry.name,
        ttl: entry.ttl,
        rr_set: RrSet::RRSIG {
            rr_set: vec![rrsig_entry],
        },
    })
}
