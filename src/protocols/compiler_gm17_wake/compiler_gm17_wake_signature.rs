use super::compiler_gm17_wake_protocol::Nonces;
use crate::{
    proof_systems::proof_system_gm17::Gm17Darkpool,
    utility::ristretto_to_string
};
use ark_bls12_377::{Parameters, Fr};
use ark_ec::bls12::Bls12;
use ark_gm17::{PreparedVerifyingKey, ProvingKey, Proof};
use curve25519_dalek_ng::ristretto::{RistrettoPoint};

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
/// holds a GM17 proof for the darkpool transaction relation
/// 
#[derive(Clone)]
pub struct CompSignature {
    pub gm17_darkpool_proof: Proof<Bls12<Parameters>>,
}

impl CompSignature {
    ///signing function
    ///outputs a signature
    pub fn sign(gm17_darkpool: &Gm17Darkpool, message_string: String, min_bal: u64, balance: u64, blinding_factor: Fr, upperbound: u64, pk: &ProvingKey<Bls12<Parameters>>) -> CompSignature {
        //compute updated balance and convert to group element
        let v = Fr::from(upperbound - (balance - min_bal));

        let gm17_darkpool_proof = gm17_darkpool.clone().prove(v, blinding_factor, message_string, pk.clone());
        return CompSignature { gm17_darkpool_proof }
    }

    ///verification function
    ///outputs a boolean indicating the verification status
    pub fn verify_signature(self, gm17_darkpool: &Gm17Darkpool, pvk: &PreparedVerifyingKey<Bls12<Parameters>>, image: Fr, message_string: String) -> bool {
        let gm17_darkpool_verification = gm17_darkpool.clone().verify(image, message_string, pvk.clone(), self.gm17_darkpool_proof);

        return gm17_darkpool_verification
    }
}