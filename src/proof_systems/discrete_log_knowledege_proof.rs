use bulletproofs::PedersenGens;
use curve25519_dalek_ng::{scalar::Scalar, ristretto::CompressedRistretto};
use rand::rngs::OsRng;
use crate::utility::{ristretto_to_string, scalar_to_string, compressed_ristretto_to_string, hash_string_to_scalar};

///
/// holds values considered as values in the proof
/// 
#[derive(Clone, Copy, Debug)]
pub struct DiscreteLogKnowledgeProof {
    pub statement: CompressedRistretto,
    pub challenge: Scalar,
    pub response: Scalar
}

///
/// initialize proof struct
/// 
impl DiscreteLogKnowledgeProof {
    pub fn to_string(self) -> String{
        return compressed_ristretto_to_string(self.statement) + &scalar_to_string(self.challenge) + &scalar_to_string(self.response); 
    }
}

///
/// holds public value (statement) of the proof
/// 
#[derive(Clone, Copy)]
pub struct DiscreteLogKnowledgeProofStruct {
    statement: CompressedRistretto
}

impl DiscreteLogKnowledgeProofStruct{
    ///
    /// initialize struct
    /// 
    pub fn new(statement: CompressedRistretto) -> DiscreteLogKnowledgeProofStruct {
        return DiscreteLogKnowledgeProofStruct { statement }
    }
    
    ///
    /// Proving function
    /// outputs a proof
    /// 
    pub fn prove(self, witness: Scalar, auxilliary_challenge_string: String) -> DiscreteLogKnowledgeProof {
        let g = PedersenGens::default().B;
        let rng = &mut OsRng;
        let r = Scalar::random(rng);
        
        let statement = (g * r).compress();
        let challenge = hash_string_to_scalar(ristretto_to_string(g) + &compressed_ristretto_to_string(self.statement) + &auxilliary_challenge_string);
        
        let response = r + challenge * witness;
        
        return DiscreteLogKnowledgeProof { statement, challenge, response };
    }
    
    ///
    /// Verification function
    /// outputs bool, indicating verification status
    /// 
    pub fn verify(self, proof: DiscreteLogKnowledgeProof,  auxilliary_challenge_string: String) -> bool {
        let g = PedersenGens::default().B;

        let self_computed_challenge = hash_string_to_scalar(ristretto_to_string(g) + &compressed_ristretto_to_string(self.statement) + &auxilliary_challenge_string);

        let challenge_verification = self_computed_challenge == proof.challenge;
        
        let verification = (g * proof.response) == proof.statement.decompress().unwrap() + (self.statement.decompress().unwrap() * proof.challenge);
        
        return challenge_verification & verification;
    }
}