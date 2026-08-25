/// Adds one, but the test suite contains a genuine defect.
pub fn add_one(x: i64) -> i64 {
    x + 1
}

#[cfg(test)]
mod tests {
    use super::add_one;

    #[test]
    fn correct_case() {
        assert_eq!(add_one(41), 42);
    }

    #[test]
    fn broken_oracle() {
        assert_eq!(add_one(0), 2, "oracle mismatch: 0 + 1 must be 1");
    }
}
