use crate::{
    CoseAlg, CoseSign1, IssuerSignedItem, MdocDocument, MobileSecurityObject, TaggedCborBytes,
};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

pub fn verify_issuer_data_auth(
    document: &MdocDocument,
    now: DateTime<Utc>,
) -> Result<MobileSecurityObject> {
    let issuer_auth = &document.issuer_signed.issuer_auth;

    // TODO: Root CA / chain validation is intentionally skipped for now.
    verify_issuer_auth_signature(issuer_auth)?;

    let payload = issuer_auth
        .payload
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("issuerAuth payload is missing"))?;
    let mso: MobileSecurityObject = minicbor::decode(payload.as_slice())
        .context("failed to decode issuerAuth payload as MobileSecurityObject")?;

    verify_doc_type(&mso, document)?;
    verify_digest_algorithm(&mso)?;
    verify_validity_info(&mso, now)?;
    verify_value_digests(document, &mso)?;

    Ok(mso)
}

fn verify_issuer_auth_signature(issuer_auth: &CoseSign1) -> Result<()> {
    let alg = resolve_alg(issuer_auth)?;
    match alg {
        CoseAlg::ES256 | CoseAlg::ES256P256 => verify_es256_signature(issuer_auth),
        _ => bail!("unsupported issuerAuth COSE algorithm: {:?}", alg),
    }
}

fn verify_es256_signature(issuer_auth: &CoseSign1) -> Result<()> {
    let cert = resolve_signing_certificate(issuer_auth)?;
    let verifying_key = verifying_key_from_certificate(cert)?;

    let payload = issuer_auth
        .payload
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("issuerAuth payload is missing"))?;

    let sig_structure = build_sig_structure(issuer_auth, payload.as_slice())?;
    let signature = Signature::from_slice(issuer_auth.signature.as_slice())
        .context("issuerAuth ES256 signature must be 64-byte raw r||s")?;

    verifying_key
        .verify(&sig_structure, &signature)
        .context("issuerAuth signature verification failed")?;

    Ok(())
}

fn resolve_alg(issuer_auth: &CoseSign1) -> Result<CoseAlg> {
    issuer_auth
        .protected
        .0
        .as_ref()
        .and_then(|h| h.alg)
        .or(issuer_auth.unprotected.alg)
        .ok_or_else(|| anyhow::anyhow!("issuerAuth algorithm is missing in COSE headers"))
}

fn resolve_signing_certificate(issuer_auth: &CoseSign1) -> Result<&Certificate> {
    let cert = issuer_auth
        .protected
        .0
        .as_ref()
        .and_then(|h| h.x5chain.as_ref())
        .or(issuer_auth.unprotected.x5chain.as_ref())
        .ok_or_else(|| anyhow::anyhow!("issuerAuth x5chain certificate is missing"))?;

    Ok(cert.into())
}

fn verifying_key_from_certificate(cert: &Certificate) -> Result<VerifyingKey> {
    let public_key_bytes = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    VerifyingKey::from_sec1_bytes(public_key_bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse issuerAuth certificate public key: {}", e))
}

fn build_sig_structure(cose_sign1: &CoseSign1, payload: &[u8]) -> Result<Vec<u8>> {
    let protected_bytes = match &cose_sign1.protected.0 {
        Some(headers) => minicbor::to_vec(headers)
            .context("failed to encode protected headers while creating Sig_structure")?,
        None => Vec::new(),
    };

    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(4)
        .context("failed to encode Sig_structure array")?;
    encoder
        .str("Signature1")
        .context("failed to encode Sig_structure context")?;
    encoder
        .bytes(&protected_bytes)
        .context("failed to encode Sig_structure body_protected")?;
    encoder
        .bytes(&[])
        .context("failed to encode Sig_structure external_aad")?;
    encoder
        .bytes(payload)
        .context("failed to encode Sig_structure payload")?;

    Ok(encoder.into_writer())
}

fn verify_doc_type(mso: &MobileSecurityObject, document: &MdocDocument) -> Result<()> {
    if mso.doc_type != document.doc_type {
        bail!(
            "MSO docType mismatch: mso='{}', document='{}'",
            mso.doc_type,
            document.doc_type
        );
    }
    Ok(())
}

fn verify_digest_algorithm(mso: &MobileSecurityObject) -> Result<()> {
    if mso.digest_algorithm != "SHA-256" {
        bail!(
            "unsupported MSO digestAlgorithm '{}'; only SHA-256 is currently supported",
            mso.digest_algorithm
        );
    }
    Ok(())
}

fn verify_validity_info(mso: &MobileSecurityObject, now: DateTime<Utc>) -> Result<()> {
    let valid_from = parse_tdate(&mso.validity_info.valid_from, "validFrom")?;
    let valid_until = parse_tdate(&mso.validity_info.valid_until, "validUntil")?;

    if valid_from > valid_until {
        bail!("invalid validityInfo: validFrom is later than validUntil");
    }
    if now < valid_from {
        bail!("MSO is not valid yet: now is before validFrom");
    }
    if now > valid_until {
        bail!("MSO expired: now is after validUntil");
    }
    Ok(())
}

fn verify_value_digests(document: &MdocDocument, mso: &MobileSecurityObject) -> Result<()> {
    let Some(issuer_namespaces) = document.issuer_signed.name_spaces.as_ref() else {
        return Ok(());
    };

    for (namespace, items) in issuer_namespaces {
        let mso_namespace_digests = mso.value_digests.get(namespace).ok_or_else(|| {
            anyhow::anyhow!("MSO missing valueDigests for namespace '{}'", namespace)
        })?;

        for item in items {
            let expected_digest =
                mso_namespace_digests
                    .get(&item.0.digest_id)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "MSO missing digest for namespace='{}', digestID={}",
                            namespace,
                            item.0.digest_id
                        )
                    })?;

            let calculated = issuer_signed_item_digest(item)?;
            if calculated.as_slice() != expected_digest.as_slice() {
                bail!(
                    "digest mismatch for namespace='{}', digestID={} (element='{}')",
                    namespace,
                    item.0.digest_id,
                    item.0.element_identifier
                );
            }
        }
    }

    Ok(())
}

fn issuer_signed_item_digest(item: &TaggedCborBytes<IssuerSignedItem>) -> Result<Vec<u8>> {
    let item_bytes = minicbor::to_vec(item).context("failed to encode IssuerSignedItemBytes")?;
    Ok(Sha256::digest(item_bytes).to_vec())
}

fn parse_tdate(raw: &str, label: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| anyhow::anyhow!("failed to parse {} as RFC3339 tdate: {}", label, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose_key::{CoseKeyPublic, Curve, KeyType};
    use crate::device_response::{DeviceAuth, DeviceSigned, IssuerSigned};
    use crate::{ElementValue, ProtectedHeaderMap};
    use minicbor::bytes::ByteVec;
    use std::collections::BTreeMap;

    #[test]
    fn verify_validity_info_accepts_now_inside_range() {
        let mso = dummy_mso();
        let now = DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(verify_validity_info(&mso, now).is_ok());
    }

    #[test]
    fn verify_value_digests_matches_issuer_namespaces() {
        let item = TaggedCborBytes(crate::IssuerSignedItem {
            digest_id: 7,
            random: ByteVec::from(vec![1, 2, 3]),
            element_identifier: "family_name".to_string(),
            element_value: ElementValue::from_string("Mustermann"),
        });

        let digest = issuer_signed_item_digest(&item).unwrap();

        let document = MdocDocument {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            issuer_signed: IssuerSigned {
                issuer_auth: CoseSign1 {
                    protected: ProtectedHeaderMap(None),
                    unprotected: crate::HeaderMap::default(),
                    payload: None,
                    signature: ByteVec::from(vec![0; 64]),
                },
                name_spaces: Some(BTreeMap::from([(
                    "org.iso.18013.5.1".to_string(),
                    vec![item],
                )])),
            },
            device_signed: DeviceSigned {
                name_spaces: crate::TaggedCborBytes(BTreeMap::new()),
                device_auth: DeviceAuth {
                    device_signature: None,
                    device_mac: None,
                },
            },
            errors: None,
        };

        let mut mso = dummy_mso();
        mso.value_digests = BTreeMap::from([(
            "org.iso.18013.5.1".to_string(),
            BTreeMap::from([(7_u64, ByteVec::from(digest))]),
        )]);

        assert!(verify_value_digests(&document, &mso).is_ok());
    }

    fn dummy_mso() -> MobileSecurityObject {
        MobileSecurityObject {
            version: "1.0".to_string(),
            digest_algorithm: "SHA-256".to_string(),
            value_digests: BTreeMap::new(),
            device_key_info: crate::DeviceKeyInfo {
                device_key: CoseKeyPublic {
                    kty: KeyType::Ec2,
                    crv: Curve::P256,
                    x: ByteVec::from(vec![1_u8; 32]),
                    y: ByteVec::from(vec![2_u8; 32]),
                },
                key_authorizations: None,
                key_info: None,
            },
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            validity_info: crate::ValidityInfo {
                signed: "2026-01-01T00:00:00Z".to_string(),
                valid_from: "2026-01-01T00:00:00Z".to_string(),
                valid_until: "2027-01-01T00:00:00Z".to_string(),
                expected_update: None,
            },
            status: None,
        }
    }
}
