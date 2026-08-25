//! Emits several megabytes of stdout, then exits successfully.

fn main() {
    let line = "x".repeat(1024);
    for _ in 0..4096 {
        println!("{line}");
    }
    eprintln!("stderr noise");
}
