use crate::proof_systems::proof_system_gm17::Gm17Darkpool;
use std::{error::Error, str::FromStr};
use ark_ff::Field;
use hex::ToHex;
use num::Num;
use num_bigint::BigInt;
use sha2::{Digest, Sha256};
use ark_bls12_377::{Parameters, Fr};
use ark_ec::bls12::Bls12;
use ark_gm17::{PreparedVerifyingKey, ProvingKey};
use curve25519_dalek_ng::{scalar::Scalar, ristretto::{RistrettoPoint, CompressedRistretto}};


//run GM17 darkpool proof setup for a specified a single party
pub fn setup_gm17_single_party(upperbound: u64) -> Result<(Gm17Darkpool, PreparedVerifyingKey<Bls12<Parameters>>, ProvingKey<Bls12<ark_bls12_377::Parameters>>), Box<dyn Error>>{
    let gm17_darkpool = Gm17Darkpool::new(upperbound.try_into().unwrap()); 
    let gm17_unwrapped: Gm17Darkpool;
    match gm17_darkpool {
        Ok(val) => {gm17_unwrapped = val}
        Err(error) => {return Err(error)}
    }

    let (pk, pvk) = gm17_unwrapped.clone().setup();

    return Ok((gm17_unwrapped, pvk, pk))

}

//run GM17 darkpool proof setup for a specified amount of parties
pub fn setup_gm17(party_amount: usize, upperbound: u64) -> Result<(Gm17Darkpool, Vec<PreparedVerifyingKey<Bls12<Parameters>>>, Vec<ProvingKey<Bls12<ark_bls12_377::Parameters>>>), Box<dyn Error>>{
    let gm17_darkpool = Gm17Darkpool::new(upperbound.try_into().unwrap()); 
    let gm17_unwrapped: Gm17Darkpool;
    match gm17_darkpool {
        Ok(val) => {gm17_unwrapped = val}
        Err(error) => {return Err(error)}
    }
    
    let mut pvk_list: Vec<PreparedVerifyingKey<Bls12<Parameters>>> = Vec::new();
    let mut pk_list: Vec<ProvingKey<Bls12<ark_bls12_377::Parameters>>> = Vec::new();
    
    for _ in 0..party_amount {
        let (pk, pvk) = gm17_unwrapped.clone().setup();
        pvk_list.push(pvk);
        pk_list.push(pk);
    }
    
    return Ok((gm17_unwrapped, pvk_list, pk_list))
}

//compute the logarithm of an upperbound among valid inputs: 2^8, 2^16, 2^32, 2^64
pub fn upperbound_log(upperbound: u64) -> Result<usize, Box<dyn Error>> {
    let u32_max = u32::MAX as u64;
    let u16_max = u16::MAX as u64;
    let u8_max = u8::MAX as u64;
    if upperbound == u64::MAX {
        return Ok(64)
    }
    else if upperbound == u32_max {
        return Ok(32)
    }
    else if upperbound == u16_max {
        return Ok(16)
    }
    else if upperbound == u8_max {
        return Ok(8)
    }
    else {
        Err(format!("Upperbound should be either 2^8, 2^16, 2^32 or 2^64").into())
    }
}

//Find previous index of list, with loop-around
pub fn find_prev_idx(idx: usize, len: usize) -> usize{
    if idx == 0 {
        return len - 1;
    }
    return idx-1;
}

//converts a RistrettoPoint to a string
pub fn ristretto_to_string(point: RistrettoPoint) -> String {
    let compressed_point = point.compress();
    
    return compressed_ristretto_to_string(compressed_point);
}

//converts a CompressedRistretto to a string
pub fn compressed_ristretto_to_string(compressed_point: CompressedRistretto) -> String {
    let point_bytes = compressed_point.to_bytes();
    let point_string = point_bytes.encode_hex::<String>();
    return point_string;
}

//converts a Scalar to a string
pub fn scalar_to_string(scalar: Scalar) -> String {
    let scalar_bytes = scalar.to_bytes();
    let scalar_string = scalar_bytes.encode_hex::<String>();
    return scalar_string;
}

//get adjacent elements in from list of group elements
pub fn get_adjacent_elements<'a>(z_list: &'a [RistrettoPoint], idx: &'a usize) -> (&'a RistrettoPoint, &'a RistrettoPoint) {
    let len = z_list.len();

    if *idx == 0 {
        return (&z_list[len-1], &z_list[1])
    }
    else if *idx == len-1 {
        return (&z_list[len-2], &z_list[0])
    }

    return (&z_list[idx-1], &z_list[idx+1])
}

//hash a string to a Scalar
pub fn hash_string_to_scalar(str: String) -> Scalar {
    let hash = Sha256::digest(str.as_bytes());
    return Scalar::from_bytes_mod_order(hash.as_slice().to_vec().try_into().unwrap());
}

//hash a string to u8 array of length 32
pub fn hash_string(input_string: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(input_string.as_bytes());

    let hash_result = hasher.finalize();

    return hash_result.into()
}

pub fn hash_string_to_fr(input_str: String) -> Fr {
    //hash string to 256 bits (32 bytes)
    let mut hasher = Sha256::new();
    hasher.update(input_str.as_bytes());
    let hash = hasher.finalize();

    //convert byte-array to decimal string<
    let big_int_val = BigInt::from_bytes_be(num_bigint::Sign::Plus, &hash);
    let decimal_string = big_int_val.to_str_radix(10);

    //convert decimal string to Fr
    let fr_val = Fr::from_str(&decimal_string).unwrap();
    return fr_val;
}

pub fn fr_to_bits<F: Field>(v: F) -> Vec<Option<F>> {
    let fr_string = v.to_string()[8..v.to_string().len() - 2].to_string();
    let fr_string_base_10 = BigInt::from_str_radix(&fr_string, 16).unwrap();
    let skrt = format!("{:0>64}", fr_string_base_10.to_str_radix(2));
    let mut fr_vec = Vec::new();
    for c in skrt.chars() {
        match c {
            '0' => fr_vec.push(Some(F::from(0 as u64))),
            '1' => fr_vec.push(Some(F::from(1 as u64))),
            _ => panic!("Invalid value"),
        }
    }
    return fr_vec;
}

pub fn mimc<F: Field>(mut v: F, mut r: F, constants: &[F]) -> F {
    let mimc_rounds = constants.len();

    for i in 0..mimc_rounds {
        let mut tmp1 = v;
        tmp1.add_assign(&constants[i]);
        let mut tmp2 = tmp1;
        tmp2.square_in_place();
        tmp2.mul_assign(&tmp1);
        tmp2.add_assign(&r);
        r = v;
        v = tmp2;
    }

    v
}