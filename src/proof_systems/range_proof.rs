use crate::utility::{hash_string, upperbound_log};
use std::error::Error;
use merlin::Transcript;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::{scalar::Scalar, ristretto::CompressedRistretto};

//struct responsible for holding all public values, and to invoke prove and verification functions
#[derive(Clone)]
pub struct RangeProofStruct {
    pc_gens: PedersenGens,
    bp_gens: BulletproofGens,
    min_bal: u64,
    upperbound: u64
}

impl RangeProofStruct {
    //Initialize generators for Pedersen Commitments and bulletproofs independently. 
    //Generators for Bulletproofs, valid for proofs up to bitsize 64 and aggregation size up to 1.
    pub fn new(min_bal: u64, upperbound: u64) -> RangeProofStruct {
        RangeProofStruct {
            pc_gens: PedersenGens::default(),
            bp_gens: BulletproofGens::new(64, 1),
            min_bal,
            upperbound,
        }
    }
    
    pub fn prove(&self, b: u64, r: Scalar, auxilliary_challenge_string: String) -> Result<RangeProof, Box<dyn Error>> {
        //assume bound up to 2^64, such that proof doesnt depend on size of "b". Which would compromise some information about "b"
        if b < self.min_bal {
            return Err(format!("minimum balance requirement was not met").into());
        }
        let v: u64 = self.upperbound - (b - self.min_bal);
        
        let mut prover_transcript = Transcript::new(b"range proof");
        prover_transcript.append_message(b"auxilliary challenge string", &hash_string(&auxilliary_challenge_string));

        let n = upperbound_log(self.upperbound).unwrap();

        let (proof, _) = RangeProof::prove_single(
            &self.bp_gens,
            &self.pc_gens,
            &mut prover_transcript,
            v,
            &r,
            n,
        ).expect("Failed to prove balance b_B in range [0, 2^min_bal_bits]");

        return Ok(proof)
    }

    pub fn verify(&self, proof: RangeProof, committed_value: CompressedRistretto, auxilliary_challenge_string: String) -> bool {
        // Verification requires a transcript with identical initial state:
        let mut verifier_transcript = Transcript::new(b"range proof");
        verifier_transcript.append_message(b"auxilliary challenge string", &hash_string(&auxilliary_challenge_string));

        let n = upperbound_log(self.upperbound).unwrap();

        proof.verify_single(&self.bp_gens, &self.pc_gens, &mut verifier_transcript, &committed_value, n)
        .is_ok()
    }
}