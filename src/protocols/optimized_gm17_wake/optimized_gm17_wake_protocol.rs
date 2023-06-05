use super::optimized_gm17_wake_signature_and_session_authentication::{OptimizedMessage, OptimizedSignatureAndSessionAuthentication};
use crate::{
    utility::{get_adjacent_elements, find_prev_idx, ristretto_to_string, mimc},
    proof_systems::{
        discrete_log_knowledege_proof::DiscreteLogKnowledgeProofStruct,
        proof_system_gm17::Gm17Darkpool
    }
};
use std::error::Error;
use rand::{rngs::OsRng, Rng};
use bulletproofs::PedersenGens;
use curve25519_dalek_ng::{scalar::Scalar, ristretto::RistrettoPoint};
use ark_bls12_377::{Fr, Parameters};
use ark_ec::bls12::Bls12;
use ark_gm17::{ProvingKey, PreparedVerifyingKey};
/// 
/// File for running Burmester Desmedt key-exchange, with optimized WAKE scheme, using GM17 SE zk-SNARK as underlying proof, for the Darkpool transaction relation
/// 

///
/// Struct responsible for holding VK from the WAKE protocol
/// 
#[derive(Clone)]
pub struct VK {
    idxs: Vec<usize>,
    z_is: Vec<RistrettoPoint>
}

impl VK {
    pub fn new(idxs: Vec<usize>, z_is: Vec<RistrettoPoint>) -> VK {
        return VK { idxs, z_is };
    }

    pub fn to_string(self) -> String {
        let mut res_string = String::new();

        for i in 0..self.idxs.len() {
            res_string += &(self.idxs[i].to_string() + &ristretto_to_string(self.z_is[i]));
        }

        return res_string;
    }
}

///
/// Struct responsible for holding Burmester Desmedt values
/// 
#[derive(Clone)]
pub struct BurmesterDesmedt {
    z_i: RistrettoPoint,
    x_i: Scalar,
}

///
/// Struct representing a single party
/// 
pub struct Party {
    //public values
    idx: usize,
    images: Vec<Fr>,
    min_bal: u64,
    gm17_darkpool: Gm17Darkpool,
    pvk_list: Vec<PreparedVerifyingKey<Bls12<Parameters>>>,
    //secret values
    balance: u64,
    blinding: Fr,
    pk: ProvingKey<Bls12<ark_bls12_377::Parameters>>,
    //optional values getting initialized during the protocol
    vk: Option<VK>,
    bd: Option<BurmesterDesmedt>
}

impl Party {
    pub fn new(idx: usize, gm17_darkpool: Gm17Darkpool, images: Vec<Fr>, min_bal: u64, balance: u64, blinding: Fr, pk: ProvingKey<Bls12<ark_bls12_377::Parameters>>, pvk_list: Vec<PreparedVerifyingKey<Bls12<Parameters>>>) -> Party {
        return Party{ 
            idx, 
            images, 
            gm17_darkpool, 
            min_bal, 
            balance, 
            blinding, 
            pk,
            pvk_list,
            vk: None, 
            bd: None 
        };
    }

    //round 1 wake, round 1 Burmester-Desmedt
    pub fn round_1(&mut self, g: RistrettoPoint, rng: &mut OsRng) -> (usize, RistrettoPoint) {
        let x_i = Scalar::random(rng);

        let z_i = g * x_i;

        self.bd = Some(BurmesterDesmedt { x_i, z_i });

        return (self.idx, z_i);
    }

    //round 2, round 2 Burmester-Desmedt
    pub fn round_2(&mut self, round_1_outputs: &Vec<(usize, RistrettoPoint)>, upperbound: u64) -> (OptimizedMessage, OptimizedSignatureAndSessionAuthentication) {
        //receiving stage
        let idxs: Vec<usize> = round_1_outputs.iter().map(|&(x, _)| x).collect();
        let z_i_list: Vec<RistrettoPoint> = round_1_outputs.iter().map(|&(_, y)| y).collect();

        let vk = VK::new(idxs, z_i_list.clone());
        self.vk = Some(vk);

        //creating & sending stage
        let (z_1, z_2) = get_adjacent_elements(&z_i_list, &self.idx);
        let x_i = self.bd.clone().unwrap().x_i;

        //compute message
        let payload = (z_2 - z_1) * x_i;
        let m_i = OptimizedMessage::new(self.idx, payload, self.vk.clone().unwrap());

        //sign message
        let signature = OptimizedSignatureAndSessionAuthentication::sign(
            &self.gm17_darkpool,
            self.images[self.idx],
            &m_i.to_string(), 
            self.min_bal, 
            self.balance, 
            self.blinding,
            (self.bd.clone().unwrap().z_i).compress(),
            self.bd.clone().unwrap().x_i,
            upperbound,
            &self.pk
        );

        return (m_i, signature);
    }

    //verification of round 2 outputs
    pub fn verify_all_round_2_outputs(&self, round_1_outputs: &Vec<(usize, RistrettoPoint)>, round_2_outputs: Vec<(OptimizedMessage, OptimizedSignatureAndSessionAuthentication)>) -> Result<(), String> {
        //iterate over all other parties' round 2 results, and assert
        for i in 0..round_1_outputs.len() {
            if i == self.idx {
                continue;
            }
            let (msg, sig_session_auth) = &round_2_outputs[i];

            //assert same VKs
            let vk_verification = msg.vk.clone().to_string() == self.vk.clone().unwrap().to_string();
            if !vk_verification {
                return Err("Invalid VK was send".to_string());
            }

            //assert session authentication, and signature verification
            let discrete_log_knowledge_proof_struct = DiscreteLogKnowledgeProofStruct::new(round_1_outputs[i].1.compress());
            let verification_status = &sig_session_auth.clone().verify_signature(&msg.to_string(), &discrete_log_knowledge_proof_struct, &self.pvk_list[i], &self.gm17_darkpool, self.images[i]);
            if !verification_status {
                return Err("Verification of signature failed".to_string())
            }
        }
        return Ok(())
    }

    //compute Burmester Desmedt key
    pub fn compute_key(&self, round1_payload: &Vec<RistrettoPoint>, round2_payload: &Vec<RistrettoPoint>) -> RistrettoPoint {
        let num_parties = round1_payload.len();

        let z = round1_payload[find_prev_idx(self.idx, num_parties)];
        let exponent = self.bd.clone().unwrap().x_i * Scalar::from(num_parties as u64);

        let mut key = z * exponent;
        for idx in 0..num_parties - 1 {
            let i = (self.idx + idx) % num_parties;
            key += round2_payload[i] * Scalar::from((num_parties - idx - 1) as u64);
        }

        return key;
    }
}

///
/// Setup function, for initializing the parties with their own secret values and public commitments
/// 
fn setup_parties(rng: &mut OsRng, party_amount: usize, min_bal: u64, balances: Vec<u64>, upperbound: u64, gm17_darkpool: Gm17Darkpool, pvk_list: Vec<PreparedVerifyingKey<Bls12<Parameters>>>, pk_list: Vec<ProvingKey<Bls12<ark_bls12_377::Parameters>>>) -> Result<Vec<Party>, Box<dyn Error>> {
    //check if length of balance list, is equal to the amount of parties denoted
    if balances.len() != party_amount {
        return Err("balances not correct length".into())
    }

    //check if upperbound is among the valid options 2^8, 2^16, 2^32, 2^64
    if upperbound != u8::MAX as u64 && upperbound != u16::MAX as u64 && upperbound != u32::MAX as u64 && upperbound != u64::MAX {
        return Err(format!("upperbound was not among the valid values: {}, {}, {}, {}\n was: {}", u8::MAX, u16::MAX, u32::MAX, u64::MAX, upperbound).into());
    }

    //statements
    let mut images: Vec<Fr> = Vec::new();

    //witnesses
    let mut blindings: Vec<Fr> = Vec::new();

    //populating statements and witnesses
    for i in 0..party_amount {
        if balances[i] < min_bal {
            return Err("one or more balances are smaller than minimum_balance".into())
        }
        let r = rng.gen();
        blindings.push(r);

        let v = Fr::from(upperbound - (balances[i] - min_bal));
        let image = mimc(v, r, &gm17_darkpool.clone().mimc_constants);
        images.push(image);
    }

    //create parties in the protocol, with their private inputs (witnesses), as well as all public information 
    let mut parties: Vec<Party> = Vec::new();
    for i in 0..party_amount {
        parties.push(Party::new(i, gm17_darkpool.clone(), images.clone(), min_bal, balances[i], blindings[i], pk_list[i].clone(), pvk_list.clone()));
    }

    return Ok(parties)
}

///Optimized 2-round WAKE
///runs a setup of key-exchange with random balances above or equal to the minimum balance
///outputs the list of keys for all the parties (which will be identical)
pub fn run_optimized_key_exchange(party_amount: usize, min_bal: u64, balances: Vec<u64>, upperbound: u64, gm17_darkpool: &Gm17Darkpool, pvk_list: &Vec<PreparedVerifyingKey<Bls12<Parameters>>>, pk_list: &Vec<ProvingKey<Bls12<ark_bls12_377::Parameters>>>) -> Result<Vec<RistrettoPoint>, Box<dyn Error>> {
    let rng = &mut OsRng;
    let pedersen_gens = PedersenGens::default();
    let g = pedersen_gens.B;

    let mut parties = setup_parties(rng, party_amount, min_bal, balances, upperbound, gm17_darkpool.clone(), pvk_list.clone(), pk_list.clone())?;

    //round 1
    let mut round_1_outputs: Vec<(usize, RistrettoPoint)> = Vec::new();
    let mut round1_payload: Vec<RistrettoPoint> = Vec::new();
    for i in 0..party_amount {
        let r1_res = &parties[i].round_1(g, rng);
        round_1_outputs.push(*r1_res);
        round1_payload.push(r1_res.1);
    }

    //round 2
    let mut round_2_outputs: Vec<(OptimizedMessage, OptimizedSignatureAndSessionAuthentication)> = Vec::new();
    let mut round2_payload: Vec<RistrettoPoint> = Vec::new();
    for i in 0..party_amount {
        let (m_i, signature) = &parties[i].round_2(&round_1_outputs, upperbound);
        round_2_outputs.push((m_i.clone(), signature.clone()));
        round2_payload.push(m_i.payload);
    }

    //verification
    for i in 0..party_amount {
        let round2_res = &parties[i].verify_all_round_2_outputs(&round_1_outputs, round_2_outputs.clone());
        if let Err(round2_err) = round2_res {
            return Err(round2_err.clone().into());
        }
    }

    //compute key
    let mut keys: Vec<RistrettoPoint> = Vec::new();
    for i in 0..party_amount {
        let key = &parties[i].compute_key(&round1_payload, &round2_payload);
        keys.push(*key);
    }

    return Ok(keys);

}