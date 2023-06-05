#[cfg(test)]
mod tests {
    use curve25519_dalek_ng::{scalar::Scalar, ristretto::RistrettoPoint};
    use rand::rngs::OsRng;
    use wake_implementation::proof_systems::range_proof::RangeProofStruct;
    use bulletproofs::{PedersenGens};
    use lazy_static::lazy_static;
    
    //setup of shared variables
    lazy_static!{
        static ref G: RistrettoPoint = PedersenGens::default().B;
        static ref H: RistrettoPoint = PedersenGens::default().B_blinding;
        static ref RNG: &'static mut OsRng = {
            let mut rng = OsRng;
            let rng_ptr: *mut OsRng = &mut rng;
            unsafe { &mut *rng_ptr }
        };
    }

    ///
    /// Test that verification yields true for case: min_bal < b
    /// with an upperbound of 2^8 - 1
    /// 
    #[test]
    fn range_proof_u8() {
        //arrange
        let b = u8::MAX as u64;
        let min_bal = 100 as u64;
        let r = Scalar::random(&mut RNG.clone());
        let upperbound = u8::MAX as u64;
        let comm = (*G)*(Scalar::from(upperbound - (b - min_bal))) + ((*H)*r);
        let range_proof_struct = RangeProofStruct::new(min_bal, upperbound);
        
        //act
        let proof = range_proof_struct.prove(b, r, String::new()).unwrap();
        
        //assert
        assert!(range_proof_struct.verify(proof, comm.compress(), String::new()))
    }

    ///
    /// Test that verification yields true for case: min_bal < b
    /// with an upperbound of 2^16 - 1
    /// 
    #[test]
    fn range_proof_u16() {
        //arrange
        let b = u16::MAX as u64;
        let min_bal = 1000;
        let r = Scalar::random(&mut RNG.clone());
        let upperbound = u16::MAX as u64;
        let comm = (*G)*(Scalar::from(upperbound - (b - min_bal))) + ((*H)*r);
        let range_proof_struct = RangeProofStruct::new(min_bal, upperbound);
        
        //act
        let proof = range_proof_struct.prove(b, r, String::new()).unwrap();
        
        //assert
        assert!(range_proof_struct.verify(proof, comm.compress(), String::new()))
    }

    ///
    /// Test that verification yields true for case: min_bal < b
    /// with an upperbound of 2^32 - 1
    /// 
    #[test]
    fn range_proof_u32() {
        //arrange
        let b = u32::MAX as u64;
        let min_bal = 1000;
        let r = Scalar::random(&mut RNG.clone());
        let upperbound = u32::MAX as u64;
        let comm = (*G)*(Scalar::from(upperbound - (b - min_bal))) + ((*H)*r);
        let range_proof_struct = RangeProofStruct::new(min_bal, upperbound);
        
        //act
        let proof = range_proof_struct.prove(b, r, String::new()).unwrap();
        
        //assert
        assert!(range_proof_struct.verify(proof, comm.compress(), String::new()))
    }

    ///
    /// Test that verification yields true for case: min_bal < b
    /// with an upperbound of 2^64 - 1
    /// 
    #[test]
    fn range_proof_u64() {
        //arrange
        let b = u64::MAX;
        let min_bal = 1000;
        let r = Scalar::random(&mut RNG.clone());
        let upperbound = u64::MAX;
        let comm = (*G)*(Scalar::from(upperbound - (b - min_bal))) + ((*H)*r);
        let range_proof_struct = RangeProofStruct::new(min_bal, upperbound);
        
        //act
        let proof = range_proof_struct.prove(b, r, String::new()).unwrap();
        
        //assert
        assert!(range_proof_struct.verify(proof, comm.compress(), String::new()))
    }
    
    ///
    /// Tests that verification yields true for case: min_bal = b
    /// 
    #[test]
    fn range_proof_eq() {
        //arrange
        let b = 4294967296u64;
        let min_bal = 4294967296u64;
        let r = Scalar::random(&mut RNG.clone());
        let upperbound = u64::MAX;
        let comm = (*G)*(Scalar::from(upperbound - (b - min_bal))) + ((*H)*r);
        let range_proof_struct = RangeProofStruct::new(min_bal, upperbound);
        
        //act
        let proof = range_proof_struct.prove(b, r, String::new()).unwrap();
        
        //assert
        assert!(range_proof_struct.verify(proof, comm.compress(), String::new()))
    }

    /// 
    /// *Negative test*
    /// Tests that verification yields false for case: min_bal > b
    /// 
    #[test]
    fn test_range_proof_neg() {
        //arrange
        let b = 4294967296u64;
        let min_bal = 4294967297u64;
        let r = Scalar::random(&mut RNG.clone());
        let upperbound = u64::MAX;
        let range_proof_struct = RangeProofStruct::new(min_bal, upperbound);
        
        //act
        let proof = range_proof_struct.prove(b, r, String::new());

        assert!(proof.err().unwrap().to_string() == "minimum balance requirement was not met");
    }
    
    ///
    /// *Negative test*
    /// Tests that verification yields false for having non-matching auxilliary challenge strings
    /// 
    #[test]
    fn test_incorrect_axilliary_challenge_strings_fails() {
        //arrange
        let b = 4294967296u64;
        let min_bal = 0u64;
        let r = Scalar::random(&mut RNG.clone());
        let upperbound = u64::MAX;
        let comm = (*G)*(Scalar::from(upperbound - (b - min_bal))) + ((*H)*r);
        let range_proof_struct = RangeProofStruct::new(min_bal, upperbound);
        
        let prover_aux_string = "prover auxilliary challenge string".to_string();
        let verifier_aux_string = "verifier auxilliary challenge string".to_string();

        let proof = range_proof_struct.prove(b, r, prover_aux_string).unwrap();
        assert!(!range_proof_struct.verify(proof, comm.compress(), verifier_aux_string))
    }
}
