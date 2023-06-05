use super::compiler_bp_wake_protocol::Nonces;
use crate::{
    proof_systems::range_proof::RangeProofStruct,
    utility::ristretto_to_string
};
use bulletproofs::RangeProof;
use curve25519_dalek_ng::{scalar::Scalar, ristretto::RistrettoPoint};


///
/// Corresponds to a WAKE compiler message
/// holds party-index, round-index, the actual contents of the message, and the nonces
/// 
#[derive(Clone)]
pub struct CompMessage {
    pub idx: usize,
    pub round_idx: usize,
    pub payload: RistrettoPoint,
    pub nonces: Nonces
}

impl CompMessage {
    pub fn new(idx: usize, round_idx: usize, message: RistrettoPoint, nonces: Nonces) -> CompMessage {
        return CompMessage { idx, round_idx, payload: message, nonces }
    }

    pub fn to_string(&self) -> String {
        return self.idx.to_string() + "##" + &self.round_idx.to_string() + "##" + &ristretto_to_string(self.payload) + "##" +  &self.nonces.clone().to_string();
    }
}

///
/// Corresponds to a WAKE compiler signature
/// holds a bulletproof rangeproof for the darkpool transaction relation
/// 
#[derive(Clone)]
pub struct CompSignature { 
    pub range_proof: RangeProof, 
}

impl CompSignature {
    ///signing function
    ///outputs a signature
    pub fn sign(message_string: String, min_bal: u64, balance: u64, blinding_factor: Scalar, upperbound: u64) -> CompSignature {
        //bulletproof proving: b >= min_bal
        //outputs new commitment to the witness
        let range_proof_struct = RangeProofStruct::new(min_bal, upperbound);
        let range_proof = range_proof_struct.prove(balance, blinding_factor, message_string.clone()).unwrap();
    
        //combine results
        let signature = CompSignature { range_proof };
    
        return signature;
    }

    ///verification function
    ///outputs a boolean indicating the verification status
    pub fn verify_signature(self, message_string: String, range_proof_struct: &RangeProofStruct, commitment: &RistrettoPoint) -> bool {
        let range_proof_verification = range_proof_struct.verify(self.range_proof.clone(), commitment.compress(), message_string.clone());
        return range_proof_verification;
    }
}