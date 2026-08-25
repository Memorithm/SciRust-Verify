//! Emits SVOP observations whose values violate the configured tolerance.
//! The program itself exits successfully: SciRust-Verify must catch the
//! divergence independently (it never trusts the program's own verdict).

fn main() {
    let observed = 1.0001; // tolerance in manifest is 1e-6
    let nan_observed = f64::NAN; // NaN against a finite oracle must fail
    println!("running oracle comparison...");
    println!(
        "SCIRUST_VERIFY_OBS_V1 {{\"kind\":\"numeric_comparison\",\"name\":\"gamma_oracle\",\"expected\":1.0,\"observed\":{observed}}}"
    );
    println!(
        "SCIRUST_VERIFY_OBS_V1 {{\"kind\":\"numeric_comparison\",\"name\":\"nan_oracle\",\"expected\":1.0,\"observed\":\"NaN\"}}"
    );
}
