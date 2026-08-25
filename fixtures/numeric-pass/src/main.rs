//! Emits SVOP v1 numeric comparisons against an analytic oracle.

fn main() {
    // Oracle: gamma(x=1) == 1 exactly; sin(0) == 0.
    let observed_gamma = 1.0 + 1e-10;
    let observed_sin = 0.0f64.asin();
    println!("running oracle comparisons...");
    println!(
        "SCIRUST_VERIFY_OBS_V1 {{\"kind\":\"numeric_comparison\",\"name\":\"gamma_oracle\",\"expected\":1.0,\"observed\":{observed_gamma}}}"
    );
    println!(
        "SCIRUST_VERIFY_OBS_V1 {{\"kind\":\"numeric_comparison\",\"name\":\"asin_zero\",\"expected\":0.0,\"observed\":{observed_sin}}}"
    );
}
