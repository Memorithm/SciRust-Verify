//! Deliberately nondeterministic computation (wall-clock based).

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    let value = (nanos % 100_000) as f64 / 7.0;
    println!("time-derived value: {value}");
    println!(
        "SCIRUST_VERIFY_OBS_V1 {{\"kind\":\"fingerprint\",\"name\":\"nanos\",\"value\":\"{nanos:032x}\"}}"
    );
}
