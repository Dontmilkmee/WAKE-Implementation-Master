#[cfg(test)]
mod tests {
    use curve25519_dalek_ng::{scalar::Scalar, ristretto::RistrettoPoint};
    use rand::rngs::OsRng;
    use wake_implementation::proof_systems::discrete_log_knowledege_proof::DiscreteLogKnowledgeProofStruct;
    use bulletproofs::PedersenGens;
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
    /// Tests correct proof construction and verification
    /// 
    #[test]
    fn discrete_log_knowledege_proof_test() {        
        let witness = Scalar::random(&mut RNG.clone());
        let public_val = (*G) * witness;
        
        let dl_knowledge_proof_struct = DiscreteLogKnowledgeProofStruct::new(public_val.compress());
        
        let proof = dl_knowledge_proof_struct.prove(witness, String::new());
        
        let verification = dl_knowledge_proof_struct.verify(proof, String::new());
        
        assert!(verification);
    }

    ///
    /// Tests verification false, for different auxilliary challenge strings are supplied to verifier and prover, respectively
    /// 
    #[test]
    fn discrete_log_knowledege_proof_test_challenge_neg() {
        let witness = Scalar::random(&mut RNG.clone());
        let public_val = (*G) * witness;
        
        let dl_knowledge_proof_struct = DiscreteLogKnowledgeProofStruct::new(public_val.compress());
        
        let proof = dl_knowledge_proof_struct.prove(witness, "prover string".to_string());
        
        let verification = dl_knowledge_proof_struct.verify(proof, "verifier string".to_string());
        
        assert!(!verification);
    }

    ///
    /// Test verification false, when wrong witness given to prove function
    /// 
    #[test]
    fn discrete_log_knowledege_proof_test_witness_neg() {        
        let witness = Scalar::random(&mut RNG.clone());
        let public_val = (*G) * witness;
        
        let dl_knowledge_proof_struct = DiscreteLogKnowledgeProofStruct::new(public_val.compress());
        
        //prove with witness + 1, instead of just witness
        let proof = dl_knowledge_proof_struct.prove(witness + Scalar::from(1 as u64), String::new());
        
        let verification = dl_knowledge_proof_struct.verify(proof, String::new());
        
        assert!(!verification);
    }

    ///
    /// Test verification false, when proof changed
    /// 
    #[test]
    fn discrete_log_knowledege_proof_test_proof_neg() {        
        let witness = Scalar::random(&mut RNG.clone());
        let public_val = (*G) * witness;
        
        let dl_knowledge_proof_struct = DiscreteLogKnowledgeProofStruct::new(public_val.compress());
        
        let real_proof = dl_knowledge_proof_struct.prove(witness, String::new());
        
        // create copies of the properly constructed proof
        let mut proof_1 = real_proof.clone();
        let mut proof_2 = real_proof.clone();
        let mut proof_3 = real_proof.clone();

        // change a single field, for each of the copies
        proof_1.statement = G.compress();
        proof_2.challenge = Scalar::from(0 as u64);
        proof_3.response = Scalar::from(0 as u64);

        // assert false verification
        let verification_1 = dl_knowledge_proof_struct.verify(proof_1, String::new());
        let verification_2 = dl_knowledge_proof_struct.verify(proof_2, String::new());
        let verification_3 = dl_knowledge_proof_struct.verify(proof_3, String::new());
        assert!(!verification_1);
        assert!(!verification_2);
        assert!(!verification_3);
    }

}