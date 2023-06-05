#[cfg(test)]
mod tests {
    use wake_implementation::protocols::compiler_bp_wake::compiler_bp_wake_protocol::run_compiler_key_exchange;
    use rand::{rngs::OsRng, Rng};
    use lazy_static::lazy_static;

    //setup of shared variables
    lazy_static!{
        static ref LARGE_MIN_BAL: u64 = 100000000;
        static ref RNG: &'static mut OsRng = {
            let mut rng = OsRng;
            let rng_ptr: *mut OsRng = &mut rng;
            unsafe { &mut *rng_ptr }
        };
        static ref UPPER_U8: u64 = u8::MAX as u64;
        static ref UPPER_U16: u64 = u16::MAX as u64;
        static ref UPPER_U32: u64 = u32::MAX as u64;
        static ref UPPER_U64: u64 = u64::MAX;
    }

    ///
    /// Runs compiler WAKE key-exchange with a range-bound upperbound of 2^8-1
    /// Asserts similar keys produced
    /// 
    #[test]
    fn test_key_exchange_u8() {
        let min_bal = 10;
        let party_amount = 10;
        
        let mut balances: Vec<u64> = Vec::new();
        for _ in 0..party_amount {
            //generate random balance larger than or equal, to the minimum balance
            let balance = RNG.clone().gen_range(min_bal..=*UPPER_U8);
            balances.push(balance);
        }
        
        let keys = run_compiler_key_exchange(party_amount, min_bal, balances, *UPPER_U8).unwrap();
        
        for i in 1..keys.len() {
            assert_eq!(keys[i-1], keys[i])
        }
    }
    
    ///
    /// Runs compiler WAKE key-exchange with a range-bound upperbound of 2^16-1
    /// Asserts similar keys produced
    /// 
    #[test]
    fn test_key_exchange_u16() {
        let min_bal = 1000;
        let party_amount = 10;
        
        let mut balances: Vec<u64> = Vec::new();
        for _ in 0..party_amount {
            //generate random balance larger than or equal, to the minimum balance
            let balance = RNG.clone().gen_range(min_bal..=*UPPER_U16);
            balances.push(balance);
        }
        
        let keys = run_compiler_key_exchange(party_amount, min_bal, balances, *UPPER_U16).unwrap();
        
        for i in 1..keys.len() {
            assert_eq!(keys[i-1], keys[i])
        }
    }
    
    ///
    /// Runs compiler WAKE key-exchange with a range-bound upperbound of 2^32-1
    /// Asserts similar keys produced
    /// 
    #[test]
    fn test_key_exchange_u32() {
        let min_bal = 10000;
        let party_amount = 10;
        
        let mut balances: Vec<u64> = Vec::new();
        for _ in 0..party_amount {
            //generate random balance larger than or equal, to the minimum balance
            let balance = RNG.clone().gen_range(min_bal..=*UPPER_U32);
            balances.push(balance);
        }
        
        let keys = run_compiler_key_exchange(party_amount, min_bal, balances, *UPPER_U32).unwrap();
        
        for i in 1..keys.len() {
            assert_eq!(keys[i-1], keys[i])
        }
    }
    
    ///
    /// Runs compiler WAKE key-exchange with a range-bound upperbound of 2^64-1
    /// Asserts similar keys produced
    /// 
    #[test]
    fn test_key_exchange_u64() {
        let party_amount = 10;
        
        let mut balances: Vec<u64> = Vec::new();
        for _ in 0..party_amount {
            //generate random balance larger than or equal, to the minimum balance
            let balance = RNG.clone().gen_range(*LARGE_MIN_BAL..=*UPPER_U64);
            balances.push(balance);
        }
        
        let keys = run_compiler_key_exchange(party_amount, *LARGE_MIN_BAL, balances, *UPPER_U64).unwrap();
        
        for i in 1..keys.len() {
            assert_eq!(keys[i-1], keys[i])
        }
    }
    
    ///
    /// *Negative test*
    /// Runs compiler WAKE key-exchange
    /// Should return error, as balances are not above the minimum required balance
    /// 
    #[test]
    fn test_key_exchange_balance_neg() {
        let party_amount = 10;
        
        let balances: Vec<u64> = vec![9, 10, 11, 12, 13, 14, 15, 16, 17, 18];
        
        let keys = run_compiler_key_exchange(party_amount, *LARGE_MIN_BAL, balances, *UPPER_U64);

        assert!(keys.err().unwrap().to_string() == "one or more balances are smaller than minimum_balance");
    }
    
    ///
    /// *Negative test*
    /// Runs compiler WAKE key-exchange
    /// Should return error, as not enough balances supplied, or too many supplied
    /// 
    #[test]
    fn test_key_exchange_balance_len_neg() {
        let party_amount = 10;
        
        let balances_one: Vec<u64> = vec![10, 11, 12, 13, 14, 15, 16, 17, 18];
        let keys = run_compiler_key_exchange(party_amount, *LARGE_MIN_BAL, balances_one, *UPPER_U64);
        assert!(keys.err().unwrap().to_string() == "balances not correct length");
        
        let balances_two: Vec<u64> = vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
        let keys = run_compiler_key_exchange(party_amount, *LARGE_MIN_BAL, balances_two, *UPPER_U64);
        assert!(keys.err().unwrap().to_string() == "balances not correct length");
    }
    
    ///
    /// *Negative test*
    /// Runs compiler WAKE key-exchange
    /// Should return error, as upppbound is not valid
    /// 
    #[test]
    fn test_upperbound_neg() {
        let party_amount = 10;
        let upperbound = 9;
        
        let balances: Vec<u64> = vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19];
        
        let keys = run_compiler_key_exchange(party_amount, *LARGE_MIN_BAL, balances, upperbound);
        
        assert!(keys.err().unwrap().to_string().starts_with("upperbound was not among the valid values:"));
    }
}