use super::optimized_gm17_wake_protocol::VK;
use crate::{
    utility::ristretto_to_string,
    proof_systems::{
        proof_system_gm17::Gm17Darkpool,
        discrete_log_knowledege_proof::{DiscreteLogKnowledgeProofStruct, DiscreteLogKnowledgeProof}
    }
};
use ark_bls12_377::{Parameters, Fr};
use ark_ec::bls12::Bls12;
use ark_gm17::{Proof, PreparedVerifyingKey, ProvingKey};
use curve25519_dalek_ng::{scalar::Scalar, ristretto::{RistrettoPoint, CompressedRistretto}};


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
/// holds a GM17 proof for the darkpool transaction relation, and a discrete logarithm knowledge proof
/// 
#[derive(Clone)]
pub struct OptimizedSignatureAndSessionAuthentication { 
    pub discrete_log_knowledge_proof: DiscreteLogKnowledgeProof,
    pub gm17_darkpool_proof: Proof<Bls12<Parameters>>,
}

impl OptimizedSignatureAndSessionAuthentication {
    ///signing function
    ///outputs a signature and the new commitment from the range proof
    pub fn sign(gm17_darkpool: &Gm17Darkpool, image: Fr, message_string: &String, min_bal: u64, balance: u64, blinding_factor: Fr, discrete_log_proof_statement: CompressedRistretto, discrete_log_proof_witness: Scalar, upperbound: u64, pk: &ProvingKey<Bls12<Parameters>>) -> OptimizedSignatureAndSessionAuthentication {
        //discrete log knowledge proof
        let discrete_log_knowledege_proof_struct = DiscreteLogKnowledgeProofStruct::new(discrete_log_proof_statement);
        let discrete_log_knowledge_proof = discrete_log_knowledege_proof_struct.prove(discrete_log_proof_witness, message_string.clone() + (&image.to_string()));

        //parse setup keys
        let v = Fr::from(upperbound - (balance - min_bal));
        let gm17_darkpool_proof = gm17_darkpool.clone().prove(v, blinding_factor, message_string.clone() + &discrete_log_knowledge_proof.to_string(), pk.clone());

        //combine results
        let signature = OptimizedSignatureAndSessionAuthentication { discrete_log_knowledge_proof, gm17_darkpool_proof};

        return signature;
    }

    ///verification function
    ///outputs a boolean indicating the verification status
    pub fn verify_signature(self, message_string: &String, discrete_log_knowledge_proof_struct: &DiscreteLogKnowledgeProofStruct, pvk: &PreparedVerifyingKey<Bls12<Parameters>>, gm17_darkpool: &Gm17Darkpool, image: Fr) -> bool {
        let discrete_log_knowledege_proof_verification = discrete_log_knowledge_proof_struct.verify(self.discrete_log_knowledge_proof.clone(), message_string.clone() + &image.to_string());

        let gm17_darkpool_verification = gm17_darkpool.clone().verify(image, message_string.clone() + &self.discrete_log_knowledge_proof.to_string(), pvk.clone(), self.gm17_darkpool_proof);
        
        return discrete_log_knowledege_proof_verification && gm17_darkpool_verification;
    }
}