use crate::utility::{upperbound_log, hash_string_to_fr, fr_to_bits};
use std::error::Error;
use rand::{rngs::OsRng, Rng};
use ark_bls12_377::{Bls12_377, Fr, FrParameters, Parameters};
use ark_ec::bls12::Bls12;
use ark_ff::{Field, Fp256};
use ark_gm17::{create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof, ProvingKey, PreparedVerifyingKey, Proof};
use ark_relations::{lc, ns, r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable}};

const MIMC_ROUNDS: usize = 322;

#[derive(Clone)]
pub struct Gm17Darkpool {
    pub mimc_constants: Vec<Fp256<FrParameters>>,
    upperbound: usize,
    rng: OsRng,
}

impl Gm17Darkpool {
    pub fn new(upperbound: usize) -> Result<Gm17Darkpool, Box<dyn Error>> {
        let upperbound_exp = upperbound_log(upperbound as u64);

        match upperbound_exp {
            Ok(_) => {}
            Err(error) => {return Err(error)}
        }

        let rng = &mut OsRng;
        let mimc_constants = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();
        return Ok(Gm17Darkpool { 
            mimc_constants,
            rng: *rng,
            upperbound: upperbound_exp.unwrap()
        })
    }

    pub fn setup(mut self) -> (ProvingKey<Bls12<ark_bls12_377::Parameters>>, PreparedVerifyingKey<Bls12<Parameters>>) {
        // Create parameters for our circuit
        let mut dummy_v_bits_vec: Vec<Option<Fr>> = Vec::new();
        for _ in 0..self.upperbound {
            dummy_v_bits_vec.push(Some(Fr::from(1 as u64)));
        }
        let dummy_r: Fr = Fr::from(1 as u64);

        let pk = {
            let c = DarkpoolCircuit::<Fr> {
                aux: None,
                v_bits: &dummy_v_bits_vec,
                r: Some(dummy_r),
                constants: &self.mimc_constants,
                upperbound: self.upperbound,
            };

            generate_random_parameters::<Bls12_377, _, _>(c, &mut self.rng).unwrap()
        };

        // Prepare the verification key (for proof verification)
        let pvk = prepare_verifying_key(&pk.vk);

        return (pk, pvk)
    }

    pub fn prove(mut self, v: Fr, r: Fr, aux: String, pk: ProvingKey<Bls12<ark_bls12_377::Parameters>>) -> Proof<Bls12<Parameters>> {
        let aux_fr = hash_string_to_fr(aux);
        let v_bits = fr_to_bits(v);
        // Create an instance of our circuit (with the witness)
        let c = DarkpoolCircuit {
            aux: Some(aux_fr),
            v_bits: &v_bits,
            r: Some(r),
            constants: &self.mimc_constants,
            upperbound: self.upperbound,
        };

        // Create a gm17 proof with our parameters.
        let proof = create_random_proof(c, &pk, &mut self.rng).unwrap();

        return proof
    }

    pub fn verify(self, image: Fr, aux: String, pvk: PreparedVerifyingKey<Bls12<Parameters>>, proof: Proof<Bls12<Parameters>>) -> bool {
        return verify_proof(
            &pvk,
            &proof,
            &[hash_string_to_fr(aux), image]
        )
        .unwrap();
    }
}

///
/// struct for proving knowledge of witness for the Darkpool transaction relation
/// 
struct DarkpoolCircuit<'a, F: Field> {
    aux: Option<F>,
    v_bits: &'a Vec<Option<F>>,
    r: Option<F>,
    constants: &'a [F],
    upperbound: usize,
}

impl<'a, F: Field> ConstraintSynthesizer<F> for DarkpoolCircuit<'a, F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        assert_eq!(self.constants.len(), MIMC_ROUNDS);

        //Define aux as input variable for circuit
        cs.new_input_variable(|| self.aux.ok_or(SynthesisError::AssignmentMissing))?;

        // Allocate the second component of the preimage.
        let mut r_value = self.r;
        let mut r = cs.new_witness_variable(|| r_value.ok_or(SynthesisError::AssignmentMissing))?;
        
        let mut v_bits_val: Vec<F> = Vec::new();
        for v_bit in self.v_bits {
            v_bits_val.push(v_bit.unwrap());
        }
        v_bits_val.reverse();

        let mut curr_exp = F::from(1 as u64);
        let mut curr_sum = F::from(1 as u64);
        let mut curr_sum_var = cs.new_witness_variable(|| Some(curr_exp).ok_or(SynthesisError::AssignmentMissing))?;
        for i in 0..self.upperbound {
            //***********************Assert v_bits are bits***********************
            //extract bit of v: b_i
            let b_i = v_bits_val[i];
            let b_i_var =
                cs.new_witness_variable(|| Some(b_i).ok_or(SynthesisError::AssignmentMissing))?;

            //define new variable: a_i = 1 - b_i
            let a_i = Some(F::from(1 as u64)).map(|mut e| {
                e.sub_assign(&b_i);
                e
            });
            let a_i_var =
                cs.new_witness_variable(|| a_i.ok_or(SynthesisError::AssignmentMissing))?;

            //enforce b_i*a_i=0
            cs.enforce_constraint(lc!() + b_i_var, lc!() + a_i_var, lc!())?;

            //****************************check v_bits v in bits****************************
            //compute 2^i*b_i
            let curr_val = Some(curr_exp).map(|mut e| {
                e.mul_assign(b_i);
                e
            });
            let curr_val_var =
                cs.new_witness_variable(|| curr_val.ok_or(SynthesisError::AssignmentMissing))?;

            //compute new sum
            let new_curr_sum = Some(curr_sum).map(|mut e| {
                e.add_assign(curr_val.unwrap());
                e
            });
            let new_curr_sum_var =
                cs.new_witness_variable(|| new_curr_sum.ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce_constraint(
                lc!() + curr_sum_var,
                lc!() + Variable::One,
                lc!() + new_curr_sum_var - curr_val_var,
            )?;

            //update sum and current exponent value
            curr_sum = new_curr_sum.unwrap();
            curr_sum_var = new_curr_sum_var;
            curr_exp.add_assign(curr_exp);
        }
    
        let mut v_value = Some(curr_sum).map(|mut e| {
            e.sub_assign(F::from(1 as u64));
            e
        });
        //v has now been reconstructed, assuming it was indeed bits of the right size. now merely compute the image
        let mut v = cs.new_witness_variable(|| v_value.ok_or(SynthesisError::AssignmentMissing))?;

        for i in 0..MIMC_ROUNDS {
            // v, r := r + (v + Ci)^3, v
            let ns = ns!(cs, "round");
            let cs = ns.cs();

            // tmp = (v + Ci)^2
            let tmp_value = (v_value).map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.square_in_place();
                e
            });
            let tmp =
                cs.new_witness_variable(|| tmp_value.ok_or(SynthesisError::AssignmentMissing))?;

            cs.enforce_constraint(
                lc!() + v + (self.constants[i], Variable::One),
                lc!() + v + (self.constants[i], Variable::One),
                lc!() + tmp,
            )?;

            // new_v = r + (v + Ci)^3
            // new_v = r + tmp * (v + Ci)
            // new_v - r = tmp * (v + Ci)
            let new_v_value = v_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.mul_assign(&tmp_value.unwrap());
                e.add_assign(&r_value.unwrap());
                e
            });

            let new_v = if i == (MIMC_ROUNDS - 1) {
                // This is the last round, v is our image and so
                // we allocate a public input.
                cs.new_input_variable(|| new_v_value.ok_or(SynthesisError::AssignmentMissing))?
            } else {
                cs.new_witness_variable(|| new_v_value.ok_or(SynthesisError::AssignmentMissing))?
            };

            cs.enforce_constraint(
                lc!() + tmp,
                lc!() + v + (self.constants[i], Variable::One),
                lc!() + new_v - r,
            )?;

            // r = v
            r = v;
            r_value = v_value;

            // v = new_v
            v = new_v;
            v_value = new_v_value;
        }

        Ok(())
    }
}