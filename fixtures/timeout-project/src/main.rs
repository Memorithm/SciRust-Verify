//! Hangs far longer than the configured verification timeout.

fn main() {
    std::thread::sleep(std::time::Duration::from_secs(120));
    println!("never printed in time");
}
