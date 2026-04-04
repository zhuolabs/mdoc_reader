use crate::{MdocDocument, MobileSecurityObject, TaggedCborBytes};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct IssuerDataAuthContext {
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct VerifiedMso {
    pub mso: MobileSecurityObject,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerDataAuthError {
    MissingIssuerAuthPayload,
    InvalidIssuerAuthPayload,
    DocTypeMismatch {
        document_doc_type: String,
        mso_doc_type: String,
    },
    InvalidValidityTimeFormat {
        field: &'static str,
    },
    ValidityTimeNotUtc {
        field: &'static str,
    },
    InvalidValidityRange {
        valid_from: String,
        valid_until: String,
    },
    NotYetValid {
        now: DateTime<Utc>,
        valid_from: DateTime<Utc>,
    },
    Expired {
        now: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    },
    UnsupportedDigestAlgorithm {
        algorithm: String,
    },
    MissingNamespaceDigests {
        namespace: String,
    },
    MissingDigestId {
        namespace: String,
        digest_id: u64,
    },
    DigestMismatch {
        namespace: String,
        digest_id: u64,
    },
    CborEncodeFailure,
}

pub fn verify_issuer_data_auth(
    doc: &MdocDocument,
    ctx: &IssuerDataAuthContext,
) -> Result<VerifiedMso, IssuerDataAuthError> {
    let payload = doc
        .issuer_signed
        .issuer_auth
        .payload
        .as_ref()
        .ok_or(IssuerDataAuthError::MissingIssuerAuthPayload)?;

    let mso: MobileSecurityObject = minicbor::decode(payload.as_slice())
        .map_err(|_| IssuerDataAuthError::InvalidIssuerAuthPayload)?;

    if doc.doc_type != mso.doc_type {
        return Err(IssuerDataAuthError::DocTypeMismatch {
            document_doc_type: doc.doc_type.clone(),
            mso_doc_type: mso.doc_type.clone(),
        });
    }

    let valid_from = parse_utc_datetime_strict("valid_from", &mso.validity_info.valid_from)?;
    let valid_until = parse_utc_datetime_strict("valid_until", &mso.validity_info.valid_until)?;

    if valid_from > valid_until {
        return Err(IssuerDataAuthError::InvalidValidityRange {
            valid_from: mso.validity_info.valid_from.clone(),
            valid_until: mso.validity_info.valid_until.clone(),
        });
    }

    if ctx.now < valid_from {
        return Err(IssuerDataAuthError::NotYetValid {
            now: ctx.now,
            valid_from,
        });
    }

    if ctx.now > valid_until {
        return Err(IssuerDataAuthError::Expired {
            now: ctx.now,
            valid_until,
        });
    }

    if mso.digest_algorithm != "SHA-256" {
        return Err(IssuerDataAuthError::UnsupportedDigestAlgorithm {
            algorithm: mso.digest_algorithm.clone(),
        });
    }

    if let Some(name_spaces) = &doc.issuer_signed.name_spaces {
        for (namespace, items) in name_spaces {
            let namespace_digests = mso.value_digests.get(namespace).ok_or_else(|| {
                IssuerDataAuthError::MissingNamespaceDigests {
                    namespace: namespace.clone(),
                }
            })?;

            for TaggedCborBytes(item) in items {
                let tagged_cbor_bytes = minicbor::to_vec(TaggedCborBytes(item.clone()))
                    .map_err(|_| IssuerDataAuthError::CborEncodeFailure)?;
                let digest = Sha256::digest(tagged_cbor_bytes);

                let expected = namespace_digests.get(&item.digest_id).ok_or_else(|| {
                    IssuerDataAuthError::MissingDigestId {
                        namespace: namespace.clone(),
                        digest_id: item.digest_id,
                    }
                })?;

                if digest.as_slice() != expected.as_slice() {
                    return Err(IssuerDataAuthError::DigestMismatch {
                        namespace: namespace.clone(),
                        digest_id: item.digest_id,
                    });
                }
            }
        }
    }

    Ok(VerifiedMso {
        mso,
        valid_from,
        valid_until,
    })
}

fn parse_utc_datetime_strict(
    field: &'static str,
    input: &str,
) -> Result<DateTime<Utc>, IssuerDataAuthError> {
    if !input.ends_with('Z') {
        return Err(IssuerDataAuthError::ValidityTimeNotUtc { field });
    }

    let dt = DateTime::parse_from_rfc3339(input)
        .map_err(|_| IssuerDataAuthError::InvalidValidityTimeFormat { field })?;

    if dt.offset().local_minus_utc() != 0 {
        return Err(IssuerDataAuthError::ValidityTimeNotUtc { field });
    }

    Ok(dt.with_timezone(&Utc))
}
