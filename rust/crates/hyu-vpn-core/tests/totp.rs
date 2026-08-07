use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use hyu_vpn_core::totp::{CounterGuard, TotpError, TotpGenerator, TotpSecret};
use serde::Deserialize;
use tempfile::tempdir;

const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[derive(Deserialize)]
struct Vector {
    unix_seconds: u64,
    code: String,
    remaining_seconds: u8,
}

#[test]
fn generates_six_digit_codes_from_shared_vectors() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("../../../../tests/fixtures/totp-vectors.json")).unwrap();
    let generator = TotpGenerator::new(TotpSecret::parse(RFC_SECRET).unwrap());

    for vector in vectors {
        let generated = generator
            .code_at(UNIX_EPOCH + Duration::from_secs(vector.unix_seconds))
            .unwrap();
        assert_eq!(generated.value, vector.code);
        assert_eq!(generated.remaining_seconds, vector.remaining_seconds);
        assert_eq!(generated.value.len(), 6);
    }
}

#[test]
fn normalizes_user_format_but_rejects_short_one_time_and_bad_padding() {
    assert_eq!(
        TotpSecret::parse("gezd-gnbv gy3tqojq\n")
            .unwrap()
            .normalized(),
        "GEZDGNBVGY3TQOJQ"
    );
    for invalid in [
        "123456",
        "ABC",
        "GEZDGNBVGY3TQOJ!",
        "GEZDGNBV=Y3TQOJQ",
        "GEZDGNBVGY3TQOJQ===",
    ] {
        assert_eq!(
            TotpSecret::parse(invalid).unwrap_err(),
            TotpError::InvalidSecret
        );
    }
}

#[test]
fn counter_guard_persists_and_refuses_reuse() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("totp-counter.json");
    let guard = CounterGuard::new(&path);
    guard.reserve(42).unwrap();
    assert_eq!(guard.last_reserved().unwrap(), Some(42));
    assert_eq!(
        guard.reserve(42).unwrap_err(),
        TotpError::CounterAlreadyUsed
    );
    assert_eq!(
        guard.reserve(41).unwrap_err(),
        TotpError::CounterAlreadyUsed
    );
    guard.reserve(43).unwrap();
    assert_eq!(fs::read_to_string(path).unwrap(), "{\"last_counter\":43}");
}

#[test]
fn concurrent_counter_reservation_has_one_winner() {
    let dir = tempdir().unwrap();
    let path = Arc::new(dir.path().join("totp-counter.json"));
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let path = Arc::clone(&path);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            CounterGuard::new(path.as_ref()).reserve(77)
        }));
    }
    barrier.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(TotpError::CounterAlreadyUsed)))
            .count(),
        1
    );
}
