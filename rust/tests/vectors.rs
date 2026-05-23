//! Vector-driven tests for kxco_verify. Loads the shared vectors.json and
//! asserts that this Rust implementation produces identical outputs to the
//! JavaScript, Go, and Python implementations.

use kxco_verify::{envelope, fingerprint, hmac_hex, kid_equals, verify_hmac};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Vectors {
    webhook_envelope: Vec<EnvelopeVec>,
    webhook_hmac:     Vec<HmacVec>,
    fingerprint:      Vec<FingerprintVec>,
}

#[derive(Debug, Deserialize)]
struct EnvelopeVec {
    name:                String,
    timestamp:           String,
    body_utf8:           String,
    expect_envelope_hex: String,
}

#[derive(Debug, Deserialize)]
struct HmacVec {
    name:            String,
    secret_utf8:     String,
    timestamp:       String,
    body_utf8:       String,
    expect_hmac_hex: String,
}

#[derive(Debug, Deserialize)]
struct FingerprintVec {
    name:        String,
    #[serde(default)]
    input_hex:   Option<String>,
    #[serde(default)]
    input_utf8:  Option<String>,
    expect_kid:  String,
}

fn load_vectors() -> Vectors {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("vectors");
    path.push("vectors.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {:?}: {}", path, e));
    serde_json::from_str(&raw).expect("vectors.json failed to parse")
}

#[test]
fn envelope_matches_vectors() {
    let v = load_vectors();
    for vec in &v.webhook_envelope {
        let got = hex::encode(envelope(&vec.timestamp, vec.body_utf8.as_bytes()));
        assert_eq!(got, vec.expect_envelope_hex, "[envelope:{}]", vec.name);
    }
}

#[test]
fn hmac_matches_vectors() {
    let v = load_vectors();
    for vec in &v.webhook_hmac {
        let got = hmac_hex(vec.secret_utf8.as_bytes(), &vec.timestamp, vec.body_utf8.as_bytes());
        assert_eq!(got, vec.expect_hmac_hex, "[hmac:{}]", vec.name);
        assert!(
            verify_hmac(
                vec.secret_utf8.as_bytes(),
                &vec.timestamp,
                vec.body_utf8.as_bytes(),
                &format!("sha256={}", got),
            ),
            "[hmac:{}] verify_hmac returned false on its own output",
            vec.name
        );
    }
}

#[test]
fn fingerprint_hex_input_matches() {
    let v = load_vectors();
    for vec in &v.fingerprint {
        let Some(h) = &vec.input_hex else { continue };
        let raw = hex::decode(h).expect("vector input_hex was not valid hex");
        let got = fingerprint(&raw);
        assert_eq!(got, vec.expect_kid, "[fingerprint:{}]", vec.name);
    }
}

#[test]
fn fingerprint_utf8_input_matches() {
    let v = load_vectors();
    for vec in &v.fingerprint {
        let Some(s) = &vec.input_utf8 else { continue };
        let got = fingerprint(s.as_bytes());
        assert_eq!(got, vec.expect_kid, "[fingerprint:{}]", vec.name);
    }
}

#[test]
fn kid_equals_constant_time() {
    assert!(kid_equals("4a7c9e2f1b3d5680", "4a7c9e2f1b3d5680"));
    assert!(!kid_equals("4a7c9e2f1b3d5680", "0000000000000000"));
    assert!(!kid_equals("short", "longer"));
}

#[test]
fn verify_hmac_accepts_prefixed_and_bare() {
    let v = load_vectors();
    let vec = &v.webhook_hmac[0];
    let bare = &vec.expect_hmac_hex;
    let prefixed = format!("sha256={}", bare);

    assert!(verify_hmac(vec.secret_utf8.as_bytes(), &vec.timestamp, vec.body_utf8.as_bytes(), bare));
    assert!(verify_hmac(vec.secret_utf8.as_bytes(), &vec.timestamp, vec.body_utf8.as_bytes(), &prefixed));

    let mut tampered = bare.to_string();
    tampered.replace_range(0..1, "0");
    assert!(!verify_hmac(vec.secret_utf8.as_bytes(), &vec.timestamp, vec.body_utf8.as_bytes(), &tampered));
}

// ── v1.1.0 — pinned_kids multi-kid rotation tests ────────────────────────

use kxco_verify::{verify_delivery, VerifyDeliveryArgs};
use std::collections::HashMap;

fn make_headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[test]
#[should_panic(expected = "mutually exclusive")]
fn pinned_kids_rejects_mixed_with_singular() {
    let zero = vec![0u8; 1952];
    let headers = make_headers(&[]);
    let kids: Vec<(&str, &[u8])> = vec![("aaaaaaaaaaaaaaaa", &zero)];
    let _ = verify_delivery(VerifyDeliveryArgs {
        headers:        &headers,
        raw_body:       b"{}",
        hmac_secret:    None,
        pq_public_key:  Some(&zero),
        pinned_kid:     Some("aaaaaaaaaaaaaaaa"),
        pinned_kids:    Some(&kids),
        window_seconds: 0,
        now_unix:       0,
    });
}

#[test]
fn pinned_kids_kid_mismatch_sets_kid_not_ok() {
    let zero = vec![0u8; 1952];
    let pq_sig = format!("ml-dsa-65={}", "00".repeat(3309));
    let now: i64 = 1_000_000_000;
    let headers = make_headers(&[
        ("x-kxco-timestamp",    "1000000000"),
        ("x-kxco-pq-kid",       "cccccccccccccccc"),
        ("x-kxco-pq-signature", pq_sig.as_str()),
    ]);
    let kids: Vec<(&str, &[u8])> = vec![
        ("aaaaaaaaaaaaaaaa", &zero),
        ("bbbbbbbbbbbbbbbb", &zero),
    ];
    let r = verify_delivery(VerifyDeliveryArgs {
        headers:        &headers,
        raw_body:       b"{}",
        hmac_secret:    None,
        pq_public_key:  None,
        pinned_kid:     None,
        pinned_kids:    Some(&kids),
        window_seconds: 0,
        now_unix:       now,
    });
    assert!(!r.kid_ok, "expected kid_ok=false for unmatched kid");
    assert!(r.resolved_kid.is_none(), "expected resolved_kid=None, got {:?}", r.resolved_kid);
    assert!(!r.pq_ok);
    assert!(!r.ok());
}

#[test]
fn pinned_kids_kid_match_resolves() {
    let zero = vec![0u8; 1952];
    let now: i64 = 1_000_000_000;
    let headers = make_headers(&[
        ("x-kxco-timestamp", "1000000000"),
        ("x-kxco-pq-kid",    "aaaaaaaaaaaaaaaa"),
        // no pq signature — testing kid resolution only
    ]);
    let kids: Vec<(&str, &[u8])> = vec![
        ("aaaaaaaaaaaaaaaa", &zero),
        ("bbbbbbbbbbbbbbbb", &zero),
    ];
    let r = verify_delivery(VerifyDeliveryArgs {
        headers:        &headers,
        raw_body:       b"{}",
        hmac_secret:    None,
        pq_public_key:  None,
        pinned_kid:     None,
        pinned_kids:    Some(&kids),
        window_seconds: 0,
        now_unix:       now,
    });
    assert!(r.kid_ok, "expected kid_ok=true for matched kid");
    assert_eq!(r.resolved_kid.as_deref(), Some("aaaaaaaaaaaaaaaa"));
    assert!(!r.pq_ok, "expected pq_ok=false (no signature provided)");
    assert!(r.timestamp_ok);
}
