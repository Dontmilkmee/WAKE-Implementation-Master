use crate::utility::{find_prev_idx, get_adjacent_elements};
use curve25519_dalek_ng::{scalar::Scalar, ristretto::RistrettoPoint, constants::RISTRETTO_BASEPOINT_POINT};
use rand::rngs::OsRng;

/// 
/// File for running Burmester Desmedt key-exchange
/// 


///
/// Struct representing a single party
/// 
#[derive(Copy, Clone, Debug)]
pub struct Party{
    idx: usize,
    alpha: RistrettoPoint,
    r: Option<Scalar>,
    z: Option<RistrettoPoint>,
}

impl Party {
    //round 1
    fn round1(&mut self, rng: &mut OsRng) -> RistrettoPoint {
        self.r = Some(Scalar::random(rng));
        self.z = Some(self.alpha * self.r.unwrap());

        return self.z.unwrap();
    }

    //round 2
    fn round2(&mut self, z_list: &Vec<RistrettoPoint>) -> RistrettoPoint {
        let (z_1, z_2) = get_adjacent_elements(&z_list, &self.idx);
        let x = (z_2 - z_1) * self.r.unwrap();

        return x;
    }

    //compute Burmester Desmedt key
    fn compute_key(&mut self, z_list: &Vec<RistrettoPoint>, x_list: &Vec<RistrettoPoint>) -> RistrettoPoint {
        let num_parties = x_list.len();

        let z = z_list[find_prev_idx(self.idx, num_parties)];
        let exponent = self.r.unwrap() * Scalar::from(num_parties as u64);
        let mut key = z * exponent;

        for idx in 0..num_parties - 1 {
            let i = (self.idx + idx) % num_parties;
            key += x_list[i] * Scalar::from((num_parties - idx - 1) as u64);
        }

        return key;
    }
}

//execute Burmester-Desmedt key-exchange with specified amount of parties
pub fn key_exchange(party_amount: usize) -> Vec<RistrettoPoint> {
    let rng = &mut OsRng;
    let alpha = RISTRETTO_BASEPOINT_POINT;

    //Initialize parties
    let mut parties: Vec<Party> = Vec::new();
    for i in 0..party_amount {
        parties.push(Party { 
            idx: i,
            r: None,
            z: None,
            alpha: alpha,
         });
    }

    let mut round_1_results: Vec<RistrettoPoint> = Vec::with_capacity(party_amount);
    for i in 0..party_amount {
        let round_1_output = &parties[i].round1(rng);
        round_1_results.push(*round_1_output);
    }

    let mut round_2_results: Vec<RistrettoPoint> = Vec::with_capacity(party_amount);
    for i in 0..party_amount {
        let round_2_output = &parties[i].round2(&round_1_results);
        round_2_results.push(*round_2_output);
    }

    let mut keys: Vec<RistrettoPoint> = Vec::new();
    for p in &mut parties {
        let key = p.compute_key(&round_1_results, &round_2_results);
        keys.push(key);
    }

    return keys;
}