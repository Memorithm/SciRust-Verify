//! Deterministic computation emitting a canonical fingerprint.
//! xorshift64* PRNG with a fixed seed; identical output on every run.

fn main() {
    let mut x: u64 = 0x243F_6A88_85A3_08D3;
    let mut acc: u64 = 0;
    for i in 0..10_000u64 {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let r = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        acc = acc.wrapping_add(r ^ i);
    }
    let scaled = (acc % 1_000_000) as f64 / 8.0;
    println!("accumulation complete: {scaled}");
    println!(
        "SCIRUST_VERIFY_OBS_V1 {{\"kind\":\"fingerprint\",\"name\":\"acc\",\"value\":\"{acc:016x}\"}}"
    );
}
