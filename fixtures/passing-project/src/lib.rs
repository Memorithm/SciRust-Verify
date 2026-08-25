/// Adds one. Oracle: trivial arithmetic identity.
pub fn add_one(x: i64) -> i64 {
    x + 1
}

#[cfg(test)]
mod tests {
    use super::add_one;

    #[test]
    fn oracle_identity() {
        assert_eq!(add_one(41), 42);
        assert_eq!(add_one(-1), 0);
    }
}
