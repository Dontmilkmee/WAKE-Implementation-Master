use super::optimized_bp_wake_protocol::VK;
use crate::{
    utility::ristretto_to_string,
    proof_systems::{
        range_proof::{RangeProofStruct},
        discrete_log_knowledege_proof::{DiscreteLogKnowledgeProofStruct, DiscreteLogKnowledgeProof}
    },
};
use bulletproofs::RangeProof;
use curve25519_dalek_ng::{scalar::Scalar, ristretto::{RistrettoPoint,CompressedRistretto}};

///
/// Corresponds to an optimized WAKE message
/// holds party-index, round-index, the actual contents of the message, and the nonces
/// 
#[derive(Clone)]
pub struct OptimizedMessage {
    pub idx: usize,
    pub payload: RistrettoPoint,
    pub vk: VK
}

impl OptimizedMessage {
    pub fn new(idx: usize, message: RistrettoPoint, vk: VK) -> OptimizedMessage {
        return OptimizedMessage { idx, payload: message, vk }
    }

    pub fn to_string(&self) -> String {
        return self.idx.to_string() + "##" + &ristretto_to_string(self.payload) + "##" +  &self.vk.clone().to_string();
    }
}

///
/// Corresponds to an optimized WAKE signature and session authentication proof
/// holds a bulletproof rangeproof for the darkpool transaction relation, and a discrete logarithm knowledge proof
/// 
#[derive(Clone)]
pub struct OptimizedSignatureAndSessionAuthentication { 
    pub discrete_log_knowledge_proof: DiscreteLogKnowledgeProof,
    pub range_proof: RangeProof, 
}

impl OptimizedSignatureAndSessionAuthentication {
    ///signing function
    ///outputs a signature
    pub fn sign(message_string: &String, min_bal: u64, balance: u64, blinding_factor: Scalar, discrete_log_proof_statement: CompressedRistretto, discrete_log_proof_witness: Scalar, upperbound: u64, commitment: &RistrettoPoint) -> OptimizedSignatureAndSessionAuthentication {
        //discrete log knowledge proof
        let discrete_log_knowledege_proof_struct = DiscreteLogKnowledgeProofStruct::new(discrete_log_proof_statement);
        let discrete_log_knowledge_proof = discrete_log_knowledege_proof_struct.prove(discrete_log_proof_witness, message_string.clone() + &ristretto_to_string(*commitment));

        //range-proof
        let range_proof_struct = RangeProofStruct::new(min_bal, upperbound);
        let range_proof = range_proof_struct.prove(balance, blinding_factor, message_string.clone() + &discrete_log_knowledge_proof.to_string()).unwrap();

        //combine results
        let signature = OptimizedSignatureAndSessionAuthentication { discrete_log_knowledge_proof, range_proof };

        return signature;
    }

    ///verification function
    ///outputs a boolean indicating the verification status
    pub fn verify_signature(self, message_string: &String, discrete_log_knowledge_proof_struct: &DiscreteLogKnowledgeProofStruct, range_proof_struct: &RangeProofStruct, commitment: &RistrettoPoint) -> bool {
        let discrete_log_knowledege_proof_verification = discrete_log_knowledge_proof_struct.verify(self.discrete_log_knowledge_proof.clone(), message_string.clone() + &ristretto_to_string(*commitment));
        let range_proof_verification = range_proof_struct.verify(self.range_proof, commitment.compress(), message_string.clone() + &self.discrete_log_knowledge_proof.to_string());
        return discrete_log_knowledege_proof_verification && range_proof_verification;
    }
}