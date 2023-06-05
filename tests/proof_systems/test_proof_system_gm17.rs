#[cfg(test)]
mod tests {
    use ark_bls12_377::Fr;
    use wake_implementation::proof_systems::proof_system_gm17::{Gm17Darkpool};
    use wake_implementation::utility::mimc;
    use rand::{rngs::OsRng, Rng};
    use lazy_static::lazy_static;
    
    //setup of shared variables
    lazy_static!{
        static ref RNG: &'static mut OsRng = {
            let mut rng = OsRng;
            let rng_ptr: *mut OsRng = &mut rng;
            unsafe { &mut *rng_ptr }
        };
        static ref STANDARD_BALANCE: u64 = 100000;
        static ref STANDARD_MIN_BAL: u64 = 100;
        static ref MIMC_ROUNDS: usize = 322;
    }
    
    #[test]
    /// Tests proof correctly validates with correct inputs to prover and verifier
    /// Performed with different combinations of v
    fn test_positive_behaviour(){
        //reusable setup
        let upperbound = u64::MAX;
        let r: Fr = RNG.clone().gen();
        let gm17_darkpool =  Gm17Darkpool::new(upperbound as usize).unwrap();
        let (pk, pvk) = gm17_darkpool.clone().setup();
        
        //test with no balance or minimum balance
        let balance = 0;
        let min_bal = 0;
        let v = Fr::from(upperbound - balance + min_bal);
        let proof = gm17_darkpool.clone().prove(v, r, "".to_string(), pk.clone());
        let image = mimc(v, r, &gm17_darkpool.mimc_constants);
        let verification_status = gm17_darkpool.clone().verify(image, "".to_string(), pvk.clone(), proof);
        assert!(verification_status);
        
        //test with equal balance and minimum balance
        let balance = 10000;
        let min_bal = 10000;
        let v = Fr::from(upperbound - balance + min_bal);
        let proof = gm17_darkpool.clone().prove(v, r, "".to_string(), pk.clone());
        let image = mimc(v, r, &gm17_darkpool.mimc_constants);
        let verification_status = gm17_darkpool.clone().verify(image, "".to_string(), pvk.clone(), proof);
        assert!(verification_status);
        
        //test with no minimum balance
        let balance = 10000;
        let min_bal = 0;
        let v = Fr::from(upperbound - balance + min_bal);
        let proof = gm17_darkpool.clone().prove(v, r, "".to_string(), pk.clone());
        let image = mimc(v, r, &gm17_darkpool.mimc_constants);
        let verification_status = gm17_darkpool.clone().verify(image, "".to_string(), pvk.clone(), proof);
        assert!(verification_status);
        
        //test with very large values 
        let balance = u64::MAX;
        let min_bal = u64::MAX;
        let v = Fr::from(upperbound - balance + min_bal);
        let proof = gm17_darkpool.clone().prove(v, r, "".to_string(), pk.clone());
        let image = mimc(v, r, &gm17_darkpool.mimc_constants);
        let verification_status = gm17_darkpool.clone().verify(image, "".to_string(), pvk.clone(), proof);
        assert!(verification_status);
        
        //test with very large values and no minimum balance
        let balance = u64::MAX;
        let min_bal = 0;
        let v = Fr::from(upperbound - balance + min_bal);
        let proof = gm17_darkpool.clone().prove(v, r, "".to_string(), pk.clone());
        let image = mimc(v, r, &gm17_darkpool.mimc_constants);
        let verification_status = gm17_darkpool.clone().verify(image, "".to_string(), pvk.clone(), proof);
        assert!(verification_status);
        
        //test with non-empty aux strings
        let v = Fr::from(upperbound - *STANDARD_BALANCE + *STANDARD_MIN_BAL);
        let proof = gm17_darkpool.clone().prove(v, r, "test123".to_string(), pk.clone());
        let image = mimc(v, r, &gm17_darkpool.mimc_constants);
        let verification_status = gm17_darkpool.clone().verify(image, "test123".to_string(), pvk.clone(), proof);
        assert!(verification_status);
    }
    
    #[test]
    fn negative_incorrect_image(){
        //reusable setup
        let upperbound = u64::MAX;
        let gm17_darkpool =  Gm17Darkpool::new(upperbound as usize).unwrap();
        let (pk, pvk) = gm17_darkpool.clone().setup();
        
        let r: Fr = RNG.clone().gen();
        let v = Fr::from(upperbound - *STANDARD_BALANCE + *STANDARD_MIN_BAL);
        let proof = gm17_darkpool.clone().prove(v, r, "".to_string(), pk.clone());
        
        //test with image not produced by correct "v"
        let incorrect_v = Fr::from(123456789);
        let image = mimc(incorrect_v, r, &gm17_darkpool.mimc_constants);
        let verification_status = gm17_darkpool.clone().verify(image, "".to_string(), pvk.clone(), proof.clone());
        assert!(!verification_status);

        //test with image not produced by correct "r"
        let incorrect_r = Fr::from(987654321);
        let image = mimc(v, incorrect_r, &gm17_darkpool.mimc_constants);
        let verification_status = gm17_darkpool.clone().verify(image, "".to_string(), pvk.clone(), proof.clone());
        assert!(!verification_status);

    }

    #[test]
    fn negative_incorrect_mimc_constants(){
        //reusable setup
        let upperbound = u64::MAX;
        let gm17_darkpool =  Gm17Darkpool::new(upperbound as usize).unwrap();
        let (pk, pvk) = gm17_darkpool.clone().setup();
        
        //test with newly generated mimc constants
        let r: Fr = RNG.clone().gen();
        let v = Fr::from(upperbound - *STANDARD_BALANCE + *STANDARD_MIN_BAL);
        let proof = gm17_darkpool.clone().prove(v, r, "".to_string(), pk.clone());

        let incorrect_mimc_constants = (0..*MIMC_ROUNDS).map(|_| RNG.clone().gen()).collect::<Vec<_>>();
        let image = mimc(v, r, &incorrect_mimc_constants);
        let verification_status = gm17_darkpool.clone().verify(image, "".to_string(), pvk.clone(), proof);
        assert!(!verification_status);
    }

    #[test]
    fn negative_unequal_aux_strings(){
        //reusable setup
        let upperbound = u64::MAX;
        let gm17_darkpool =  Gm17Darkpool::new(upperbound as usize).unwrap();
        let (pk, pvk) = gm17_darkpool.clone().setup();
        
        //test with different aux strings for prover and verifier
        let r: Fr = RNG.clone().gen();
        let v = Fr::from(upperbound - *STANDARD_BALANCE + *STANDARD_MIN_BAL);
        let prover_aux_string = "test123";
        let proof = gm17_darkpool.clone().prove(v, r, prover_aux_string.to_string(), pk.clone());

        let image = mimc(v, r, &gm17_darkpool.mimc_constants);
        let verifier_aux_string = "different string";
        let verification_status = gm17_darkpool.clone().verify(image, verifier_aux_string.to_string(), pvk.clone(), proof);
        assert!(!verification_status);
    }
}