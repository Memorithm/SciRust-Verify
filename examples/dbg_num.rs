fn main() {
    use scirust_verify_numerics::*;
    let stdout = "SCIRUST_VERIFY_OBS_V1 {\"kind\":\"metric\",\"name\":\"latency\",\"value\":1.5}\n";
    match parse_observations(stdout) {
        Ok(o) => println!("OK {:?}", o),
        Err(e) => println!("ERR {:?}", e),
    }
}
