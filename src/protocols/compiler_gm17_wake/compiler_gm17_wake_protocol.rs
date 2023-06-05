use crate::{
    proof_systems::proof_system_gm17::Gm17Darkpool,
    protocols::compiler_gm17_wake::compiler_gm17_wake_signature::{CompMessage, CompSignature},
    utility::{get_adjacent_elements, find_prev_idx, scalar_to_string, mimc}
};
use rand::{Rng, rngs::OsRng};
use std::error::Error;
use ark_bls12_377::{Fr, Parameters};
use ark_ec::bls12::Bls12;
use ark_gm17::{PreparedVerifyingKey, ProvingKey};
use bulletproofs::PedersenGens;
use curve25519_dalek_ng::{scalar::Scalar, ristretto::RistrettoPoint};

/// 
/// File for running Burmester Desmedt key-exchange, with compiler WAKE scheme, using GM17 SE zk-SNARK as underlying proof, for the Darkpool transaction relation
/// 


///
/// Struct responsible for holding nonces from the WAKE protocol
/// 
#[derive(Clone)]
pub struct Nonces {
    idxs: Vec<usize>,
    scalars: Vec<Scalar>
}

impl Nonces {
    pub fn new(idxs: Vec<usize>, scalars: Vec<Scalar>) -> Nonces {
        return Nonces { idxs, scalars };
    }

    pub fn to_string(self) -> String {
        let mut res_string = String::new();

        for i in 0..self.idxs.len() {
            res_string += &(self.idxs[i].to_string() + &scalar_to_string(self.scalars[i]));
        }

        return res_string;
    }
}

///
/// Struct responsible for holding Burmester Desmedt values
/// 

#[derive(Clone)]
pub struct BurmesterDesmedt {
    r: Scalar,
}

///
/// Struct representing a single party
/// 
pub struct Party {
    //public values
    idx: usize,
    min_bal: u64,
    images: Vec<Fr>,
    pvk_list: Vec<PreparedVerifyingKey<Bls12<Parameters>>>,
    //secret values
    gm17_darkpool: Gm17Darkpool,
    balance: u64,
    blinding: Fr,
    pk: ProvingKey<Bls12<ark_bls12_377::Parameters>>,
    //optional values getting initialized during the protocol
    nonces: Option<Nonces>,
    bd: Option<BurmesterDesmedt>
}

impl Party {
    pub fn new(idx: usize, gm17_darkpool: Gm17Darkpool, images: Vec<Fr>, min_bal: u64, balance: u64, blinding: Fr, pk: ProvingKey<Bls12<ark_bls12_377::Parameters>>, pvk_list: Vec<PreparedVerifyingKey<Bls12<Parameters>>>) -> Party {
        return Party{ 
            idx,
            min_bal, 
            images, 
            pvk_list,
            gm17_darkpool,
            balance, 
            blinding, 
            pk,
            nonces: None, 
            bd: None 
        };
    }

    //round 1 wake
    pub fn round_1(&self, rng: &mut OsRng) -> (usize, Scalar) {
        let nonce = Scalar::random(rng);

        return (self.idx, nonce)
    }

    //receive & process round 1 messages
    pub fn round1_recieve(&mut self, round_1_outputs: &Vec<(usize, Scalar)>) {
        let (idxs, scalars): (Vec<usize>, Vec<Scalar>) = round_1_outputs.iter().map(|(x, y)| (*x, y.clone())).unzip();

        let nonces = Nonces::new(idxs, scalars);

        self.nonces = Some(nonces);
    }

    //round 2 wake. round 1 Burmester-Desmedt
    pub fn round_2(&mut self, g: RistrettoPoint, rng: &mut OsRng, upperbound: u64) -> (CompMessage, CompSignature) {
        let r = Scalar::random(rng);
        let z = g * r;

        let bd = BurmesterDesmedt { r };
        self.bd = Some(bd);

        let message = CompMessage::new(self.idx, 2, z, self.nonces.clone().unwrap());

        let signature = CompSignature::sign(
            &self.gm17_darkpool, 
            message.to_string(), 
            self.min_bal, 
            self.balance, 
            self.blinding, 
            upperbound, 
            &self.pk
        );

        return (message, signature)
    }

    //round 3 wake. round 2 Burmester-Desmedt
    pub fn round_3(&self, z_list: &Vec<RistrettoPoint>, upperbound: u64) -> (CompMessage, CompSignature) {
        let (z_1, z_2) = get_adjacent_elements(&z_list, &self.idx);
        let r = self.bd.clone().unwrap().r;
        let x = (z_2 - z_1) * r;

        let message = CompMessage::new(self.idx, 3, x, self.nonces.clone().unwrap());

        let signature = CompSignature::sign(
            &self.gm17_darkpool, 
            message.to_string(), 
            self.min_bal, 
            self.balance, 
            self.blinding,
            upperbound, 
            &self.pk
        );

        return (message, signature)
    }
    
    //receive & process round 2/3 messages
    pub fn round_recieve(&self, prev_round_res: Vec<(CompMessage, CompSignature)>, round_idx: usize) -> Result<(), String> {
        //check if un-equal vector lengths from input
        if self.images.len() != prev_round_res.len() {
            return Err(format!("Invalid length expected: {}, found {}", prev_round_res.len(), self.images.len()))
        }
    
        //iterate over all other parties' round 2 results, and assert
        for i in 0..prev_round_res.len() {
            if i == self.idx {
                continue;
            }

            let curr_message = &prev_round_res[i].0;
            
            //assert correct round number
            if curr_message.round_idx != round_idx {
                return Err(format!("Incorrect round number {}", curr_message.round_idx))
            }
    
            //assert same nonces
            if curr_message.nonces.clone().to_string() != self.nonces.clone().unwrap().to_string() {
                return Err("Invalid nonces".to_string())
            }
            
            //assert correct signature
            let verification_status = &prev_round_res[i].1.clone().verify_signature(
                &self.gm17_darkpool, 
                &self.pvk_list[i],
                self.images[i], 
                curr_message.to_string(),
            );
            if !verification_status {
                return Err("Verification of signature failed".to_string())
            }
        }   
        return Ok(())
    }
    
    //compute Burmester Desmedt key
    pub fn compute_key(&self, z_list: &Vec<RistrettoPoint>, x_list: &Vec<RistrettoPoint>) -> RistrettoPoint {
        let num_parties = x_list.len();

        let z = z_list[find_prev_idx(self.idx, num_parties)];
        let exponent = self.bd.clone().unwrap().r * Scalar::from(num_parties as u64);
        let mut key = z * exponent;

        for idx in 0..num_parties - 1 {
            let i = (self.idx + idx) % num_parties;
            key += x_list[i] * Scalar::from((num_parties - idx - 1) as u64);
        }

        return key;
    }

}

///
/// Setup function, for initializing the parties with their own secret values and public images
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

    //public images
    let mut images: Vec<Fr> = Vec::new();

    //blindings for hashing
    let mut blindings: Vec<Fr> = Vec::new();

    //populating images and blindings
    for i in 0..party_amount {
        //returrn error if insufficient balances 
        if balances[i] < min_bal {
            return Err("one or more balances are smaller than minimum_balance".into())
        }
        
        //generate random hash blinding
        let r: Fr = rng.gen();
        blindings.push(r);

        //compute & hash: 2^n-1 - b + B
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

// Implements the compiler-version of the WAKE protocol 
pub fn run_compiler_key_exchange(party_amount: usize, min_bal: u64, balances: Vec<u64>, upperbound: u64, gm17_darkpool: &Gm17Darkpool, pvk_list: &Vec<PreparedVerifyingKey<Bls12<Parameters>>>, pk_list: &Vec<ProvingKey<Bls12<ark_bls12_377::Parameters>>>) -> Result<Vec<RistrettoPoint>, Box<dyn Error>> {
    let rng = &mut OsRng;
    let pedersen_gens = PedersenGens::default();
    let g = pedersen_gens.B;

    let mut parties = setup_parties(rng, party_amount, min_bal, balances, upperbound, gm17_darkpool.clone(), pvk_list.clone(), pk_list.clone())?;
    
    //round 1
    let mut round1_outputs: Vec<(usize, Scalar)> = Vec::new();
    for i in 0..party_amount {
        let r1_res = &parties[i].round_1(rng);
        round1_outputs.push(*r1_res);
    }
    
    //round 1 receive
    for i in 0..party_amount {
        let _ = &parties[i].round1_recieve(&round1_outputs);
    }

    //round 2 execution and receive
    let mut round2_outputs: Vec<(CompMessage, CompSignature)> = Vec::new();
    let mut round2_outputs_payloads: Vec<RistrettoPoint> = Vec::new();
    for i in 0..party_amount {
        let (message, signature) = &parties[i].round_2(g, rng, upperbound);
        round2_outputs_payloads.push(message.payload);
        round2_outputs.push((message.clone(), signature.clone()));
    }
    for i in 0..party_amount {
        let round2_res = &parties[i].round_recieve(round2_outputs.clone(), 2);
        if let Err(round2_err) = round2_res {
            return Err(round2_err.clone().into());
        }
    }

    //round 3 execution & receive
    let mut round3_outputs: Vec<(CompMessage, CompSignature)> = Vec::new();
    let mut round3_outputs_payloads: Vec<RistrettoPoint> = Vec::new();
    for i in 0..party_amount {
        let (message, signature) = &parties[i].round_3(&round2_outputs_payloads, upperbound);
        round3_outputs_payloads.push(message.payload);
        round3_outputs.push((message.clone(), signature.clone()));
    }
    for i in 0..party_amount {
        let round3_res = &parties[i].round_recieve(round3_outputs.clone(), 3);
        if let Err(round3_err) = round3_res {
            return Err(round3_err.clone().into());
        }
    }
    
    //compute key
    let mut keys: Vec<RistrettoPoint> = Vec::new();
    for i in 0..party_amount {
        let key = &parties[i].compute_key(&round2_outputs_payloads, &round3_outputs_payloads);
        keys.push(*key);
    }

    return Ok(keys)
}
