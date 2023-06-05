#[cfg(test)]
mod tests {
    use wake_implementation::protocols::burmester_desmedt::key_exchange::key_exchange;
    #[test]
    fn test_compute_key() {
        let party_amount = 10;
        let keys = key_exchange(party_amount);
        
        for i in 1..party_amount {
            assert_eq!(keys[i-1], keys[i]);
        }
    }
}