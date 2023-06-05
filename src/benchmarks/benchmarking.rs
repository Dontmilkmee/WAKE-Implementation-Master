use crate::{
    utility::{
        setup_gm17, 
        setup_gm17_single_party,
        mimc
    },
    proof_systems::{
        range_proof::RangeProofStruct, 
        discrete_log_knowledege_proof::DiscreteLogKnowledgeProofStruct, 
    },
    protocols::{
        compiler_bp_wake::{compiler_bp_wake_protocol::{run_compiler_key_exchange, Nonces}, compiler_bp_wake_signature::{CompSignature, CompMessage}},
        optimized_bp_wake::{optimized_bp_wake_protocol::{run_optimized_key_exchange, VK}, optimized_bp_wake_signature_and_session_authentication::{OptimizedSignatureAndSessionAuthentication, OptimizedMessage}},
        compiler_gm17_wake::{compiler_gm17_wake_protocol::run_compiler_key_exchange as run_gm17_compiler_key_exchange, compiler_gm17_wake_signature::CompSignature as GM17CompSignature},
        optimized_gm17_wake::{optimized_gm17_wake_protocol::run_optimized_key_exchange as run_gm17_optimized_key_exchange, optimized_gm17_wake_signature_and_session_authentication::OptimizedSignatureAndSessionAuthentication as GM17OptimizedSignatureAndSessionAuthentication},
        burmester_desmedt::key_exchange::key_exchange,
    }
};
use csv::WriterBuilder;
use std::{error::Error, fs::File, time::Instant};
use rand::{rngs::OsRng, Rng};
use ark_bls12_377::{Fr, Parameters};
use ark_ec::{PairingEngine, bls12::Bls12};
use bulletproofs::PedersenGens;
use curve25519_dalek_ng::{scalar::Scalar, ristretto::CompressedRistretto};

const UPPERBOUNDS: [u64; 4] = [u8::MAX as u64, u16::MAX as u64, u32::MAX as u64, u64::MAX];
const MIN_BAL: u64 = 10;

#[cfg(not(tarpaulin_include))]
pub fn benchmark_sizes() -> Result<(), Box<dyn Error>> {
    let mut data = Vec::new();
    
    let g1_affine_size = std::mem::size_of::<<Bls12<Parameters> as PairingEngine>::G1Affine>();
    let g2_affine_size = std::mem::size_of::<<Bls12<Parameters> as PairingEngine>::G2Affine>();
    let comp_ris_size = std::mem::size_of::<CompressedRistretto>();
    let scalar_size = std::mem::size_of::<Scalar>();
    
    let logs_of_upperbounds = [3, 4, 5, 6];
    
    for l in logs_of_upperbounds {
        let discreet_log_size = 2*scalar_size + comp_ris_size;
        let comp_size = (4+(2*l))*comp_ris_size + (3+2)*scalar_size;
        let opti_size = comp_size + discreet_log_size;
        let gm17_comp_size = 2*g1_affine_size + g2_affine_size;
        let gm17_opti_size = gm17_comp_size + discreet_log_size;
        
        data.push(
            (comp_size.to_string(),
            opti_size.to_string(),
            gm17_comp_size.to_string(),
            gm17_opti_size.to_string()
        )
    );
}

let mut writer = WriterBuilder::new()
.delimiter(b',')
.from_writer(File::create("src/benchmarks/data/signature_sizes.csv")?);

for (comp_size, opti_size, gm17_comp_size, gm17_opti_size) in &data {
    writer.write_record(
        &[comp_size, opti_size, gm17_comp_size, gm17_opti_size]
    )?;
}

Ok(())
}

#[cfg(not(tarpaulin_include))]
pub fn benchmark_protocol(sample_size: u128, party_amounts: &Vec<usize>) -> Result<(), Box<dyn Error>> {
    println!("#############################Benchmark of protocols initiated############################");
    let mut data = Vec::new();
    let rng = &mut OsRng;
    
    //iterate over party amounts
    for party_amount in party_amounts {
        println!("new party amount: {:?}", party_amount);
        //iterate over different upperbounds
        for (i, upperbound) in UPPERBOUNDS.iter().enumerate() {
            println!("upperbound: {}", upperbound);
            
            //gm17 setup values
            let (gm17_darkpool, pvk_list, pk_list) = setup_gm17(*party_amount, *upperbound)?;
            
            let mut total_time_elapsed_compiler: u128 = 0;
            let mut total_time_elapsed_optimized: u128 = 0;
            let mut total_time_elapsed_gm17_compiler: u128 = 0;
            let mut total_time_elapsed_gm17_optimized: u128 = 0;
            let mut total_time_elapsed_bd: u128 = 0;
            
            //run over sample-size and take average of results
            for i in 0..sample_size{
                println!("iteration {}", i);
                
                let mut balances: Vec<u64> = Vec::new();
                for _i in 0..*party_amount {
                    let balance = rng.gen_range(MIN_BAL..=*upperbound);
                    balances.push(balance);
                }  
                
                //run and benchmark compiler WAKE key exchange protocol
                let start_time_compiler = Instant::now();
                let _ = run_compiler_key_exchange(*party_amount, MIN_BAL, balances.to_vec(), *upperbound).unwrap();
                let time_elapsed_compiler = start_time_compiler.elapsed().as_nanos();
                
                //run and benchmark optimized WAKE key exchange protocol
                let start_time_optimized = Instant::now();
                let _ = run_optimized_key_exchange(*party_amount, MIN_BAL, balances.to_vec(), *upperbound).unwrap();
                let time_elapsed_optimized = start_time_optimized.elapsed().as_nanos();
                
                //run and benchmark GM17 compiler WAKE key exchange protocol
                let start_time_gm17_compiler = Instant::now();
                let _ = run_gm17_compiler_key_exchange(*party_amount, MIN_BAL, balances.to_vec(), *upperbound, &gm17_darkpool, &pvk_list, &pk_list);
                let time_elapsed_gm17_compiler = start_time_gm17_compiler.elapsed().as_nanos();
                
                //run and benchmark GM17 optimized WAKE key exchange protocol
                let start_time_gm17_optimized = Instant::now();
                let _ = run_gm17_optimized_key_exchange(*party_amount, MIN_BAL, balances, *upperbound, &gm17_darkpool, &pvk_list, &pk_list);
                let time_elapzed_gm17_optimized = start_time_gm17_optimized.elapsed().as_nanos();
                
                //run and benchmark Burmester-Desmedt key exchange protocol
                let start_time_bd = Instant::now();
                let _ = key_exchange(*party_amount);
                let time_elapsed_bd = start_time_bd.elapsed().as_nanos();
                
                total_time_elapsed_compiler += time_elapsed_compiler;
                total_time_elapsed_optimized += time_elapsed_optimized;
                total_time_elapsed_gm17_compiler += time_elapsed_gm17_compiler;
                total_time_elapsed_gm17_optimized += time_elapzed_gm17_optimized;
                total_time_elapsed_bd += time_elapsed_bd;
            }
            
            let upperbound_log = match i {
                0 => "8",
                1 => "16",
                2 => "32",
                3 => "64",
                _ => return Err("Wrong upperbound exp".into())
            };
            data.push(
                (upperbound_log.to_string(), 
                party_amount.to_string(), 
                (total_time_elapsed_compiler/sample_size).to_string(), 
                ((total_time_elapsed_compiler/sample_size)/(*party_amount) as u128).to_string(), 
                (total_time_elapsed_optimized/sample_size).to_string(), 
                ((total_time_elapsed_optimized/sample_size)/(*party_amount) as u128).to_string(),
                (total_time_elapsed_bd/sample_size).to_string(),
                ((total_time_elapsed_bd/sample_size)/(*party_amount) as u128).to_string(),
                (total_time_elapsed_gm17_compiler/sample_size).to_string(),
                ((total_time_elapsed_gm17_compiler/sample_size)/(*party_amount) as u128).to_string(),
                (total_time_elapsed_gm17_optimized/sample_size).to_string(),
                ((total_time_elapsed_gm17_optimized/sample_size)/(*party_amount) as u128).to_string()
            ));
        }
    }
    
    let mut writer = WriterBuilder::new()
    .delimiter(b',')
    .from_writer(File::create("src/benchmarks/data/optimized_and_compiler_output.csv")?);
    
    for (upperbound_exp, 
        party_amount, 
        time_compiler, 
        time_compiler_pr, 
        time_optimized, 
        time_optimized_pr, 
        time_bd, 
        time_bd_pr, 
        time_gm17_comp, 
        time_gm17_comp_pr, 
        time_gm17_opti, 
        time_gm17_opti_pr) in &data {
            writer.write_record(
                &[upperbound_exp, 
                party_amount, 
                time_compiler, 
                time_compiler_pr, 
                time_optimized, 
                time_optimized_pr, 
                time_bd, 
                time_bd_pr, 
                time_gm17_comp, 
                time_gm17_comp_pr, 
                time_gm17_opti, 
                time_gm17_opti_pr]
            )?;
        }
        
        writer.flush()?;
        
        println!("#############################Benchmark of protocols finished#############################");
        
        Ok(())
    }
    
    #[cfg(not(tarpaulin_include))]
    pub fn benchmark_signature_and_session_authentication(sample_size: u128) -> Result<(), Box<dyn Error>> {
        println!("###############Benchmark of signature and session authentication initiated###############");
        let mut data = Vec::new();
        let rng = &mut OsRng;
        let g = PedersenGens::default().B;
        let h = PedersenGens::default().B_blinding;
        
        for (i, upperbound) in UPPERBOUNDS.iter().enumerate() {
            println!("upperbound: {}", upperbound);
            let balance = rng.gen_range(MIN_BAL..=*upperbound);
            
            //blindings
            let og_blinding = Scalar::random(rng);
            let og_blinding_fr: Fr = rng.gen();
            
            //bulletproof setup values
            let og_commitment = (g * Scalar::from(upperbound-(balance - MIN_BAL))) + (h * og_blinding);
            let vk_ristretto = g * Scalar::random(rng);
            let x_i = Scalar::random(rng);
            let x = g * Scalar::random(rng) * x_i;
            let z_i = g * x_i;
            
            //messages
            let vk_struct = VK::new(vec![1], vec![vk_ristretto]);
            let compiler_message = CompMessage::new(1, 2, x, Nonces::new(Vec::new(), Vec::new()));
            let optimized_message = OptimizedMessage::new(1, x, vk_struct);
            
            //gm17 setup values
            let (gm17_darkpool, pvk, pk) = setup_gm17_single_party(*upperbound)?;
            
            //total bullet time
            let mut total_time_elapsed_compiler_sig: u128 = 0;
            let mut total_time_elapsed_compiler_verify: u128 = 0;
            let mut total_time_elapsed_optimized_sig: u128 = 0;
            let mut total_time_elapsed_optimized_verify: u128 = 0;
            
            //total gm17 time
            let mut total_time_elapsed_gm17_compiler_sig: u128 = 0;
            let mut total_time_elapsed_gm17_compiler_verify: u128 = 0;
            let mut total_time_elapsed_gm17_optimized_sig: u128 = 0;
            let mut total_time_elapsed_gm17_optimized_verify: u128 = 0;
            
            
            for i in 0..sample_size {
                println!("iteration {}", i+1);
                
                
                //time compiler proof
                let start_time_compiler_sig = Instant::now();
                let sig = CompSignature::sign(compiler_message.to_string(), MIN_BAL, balance, og_blinding, *upperbound);
                total_time_elapsed_compiler_sig += start_time_compiler_sig.elapsed().as_nanos();
                
                //time compiler verifiaction
                let start_time_compiler_verify = Instant::now();
                let range_proof = RangeProofStruct::new(MIN_BAL, *upperbound);
                let _ = sig.verify_signature(compiler_message.to_string(), &range_proof, &og_commitment);
                total_time_elapsed_compiler_verify += start_time_compiler_verify.elapsed().as_nanos();
                
                //time optimized proof
                let start_time_optimized_sig = Instant::now();
                let optimized_sig = OptimizedSignatureAndSessionAuthentication::sign(&optimized_message.to_string(), MIN_BAL, balance, og_blinding, z_i.compress(), x_i, *upperbound, &og_commitment);
                total_time_elapsed_optimized_sig += start_time_optimized_sig.elapsed().as_nanos();
                
                //time optimized verification
                let start_time_optimized_verify = Instant::now();
                let dl_proof = DiscreteLogKnowledgeProofStruct::new(z_i.compress());
                let range_proof = RangeProofStruct::new(MIN_BAL, *upperbound);
                let _ = optimized_sig.clone().verify_signature(&optimized_message.to_string(), &dl_proof, &range_proof, &og_commitment);
                total_time_elapsed_optimized_verify += start_time_optimized_verify.elapsed().as_nanos();
                
                //time gm17 compiler proof
                let start_time_gm17_comp_sig = Instant::now();
                let gm17_comp_sig = GM17CompSignature::sign(&gm17_darkpool, compiler_message.to_string(), MIN_BAL, balance, og_blinding_fr, *upperbound, &pk);
                total_time_elapsed_gm17_compiler_sig += start_time_gm17_comp_sig.elapsed().as_nanos();
                
                //time gm17 compiler verification
                let v = Fr::from(upperbound - (balance - MIN_BAL));
                let image = mimc(v, og_blinding_fr, &gm17_darkpool.mimc_constants);
                let start_time_gm17_comp_ver = Instant::now();
                let _ = gm17_comp_sig.verify_signature(&gm17_darkpool, &pvk, image, compiler_message.to_string());
                total_time_elapsed_gm17_compiler_verify += start_time_gm17_comp_ver.elapsed().as_nanos();
                
                //time gm17 optimized proof
                let image = mimc(v, og_blinding_fr, &gm17_darkpool.mimc_constants);
                let start_time_gm17_opti_sig = Instant::now();
                let gm17_opti_sig = GM17OptimizedSignatureAndSessionAuthentication::sign(&gm17_darkpool, image, &optimized_message.to_string(), MIN_BAL, balance, og_blinding_fr, z_i.compress(), x_i, *upperbound, &pk);
                total_time_elapsed_gm17_optimized_sig += start_time_gm17_opti_sig.elapsed().as_nanos();
                
                //time gm17 optimized verification
                let image = mimc(v, og_blinding_fr, &gm17_darkpool.mimc_constants);
                let start_time_gm17_opti_ver = Instant::now();
                let dl_proof = DiscreteLogKnowledgeProofStruct::new(z_i.compress());
                let _ = gm17_opti_sig.verify_signature(&optimized_message.to_string(), &dl_proof, &pvk, &gm17_darkpool, image);
                total_time_elapsed_gm17_optimized_verify += start_time_gm17_opti_ver.elapsed().as_nanos();
            }
            
            let time_elapsed_comp_sig = total_time_elapsed_compiler_sig / sample_size;
            let time_elapsed_comp_verify = total_time_elapsed_compiler_verify / sample_size;
            let time_elapsed_optimized_sig = total_time_elapsed_optimized_sig / sample_size;
            let time_elapsed_optimized_verify = total_time_elapsed_optimized_verify / sample_size;
            
            let time_elapsed_gm17_comp_sig = total_time_elapsed_gm17_compiler_sig  / sample_size;
            let time_elapsed_gm17_comp_ver = total_time_elapsed_gm17_compiler_verify / sample_size;
            let time_elapsed_gm17_opti_sig = total_time_elapsed_gm17_optimized_sig / sample_size;
            let time_elapsed_gm17_opti_ver = total_time_elapsed_gm17_optimized_verify / sample_size;
            
            let upperbound_exp = match i {
                0 => "8",
                1 => "16",
                2 => "32",
                3 => "64",
                _ => return Err("Wrong upperbound exp".into())
            };
            
            data.push(
                (upperbound_exp.to_string(),
                time_elapsed_comp_sig.to_string(), 
                time_elapsed_comp_verify.to_string(), 
                time_elapsed_optimized_sig.to_string(), 
                time_elapsed_optimized_verify.to_string(),
                time_elapsed_gm17_comp_sig.to_string(),
                time_elapsed_gm17_comp_ver.to_string(),
                time_elapsed_gm17_opti_sig.to_string(),
                time_elapsed_gm17_opti_ver.to_string(),
            )
        );
    }
    
    let mut writer = WriterBuilder::new()
    .delimiter(b',')
    .from_writer(File::create("src/benchmarks/data/sign_and_verify_outputs.csv")?);
    
    for (upperbound_exp, 
        time_elapsed_compiler_sig, 
        time_elapsed_compiler_verify, 
        time_elapsed_optimized_sig, 
        time_elapsed_optimized_verify, 
        time_elapsed_gm17_comp_sig, 
        time_elapsed_gm17_comp_ver, 
        time_elapsed_gm17_opti_sig, 
        time_elapsed_gm17_opti_ver
    ) in &data {
        writer.write_record(
            &[upperbound_exp, 
            time_elapsed_compiler_sig, 
            time_elapsed_compiler_verify, 
            time_elapsed_optimized_sig, 
            time_elapsed_optimized_verify, 
            time_elapsed_gm17_comp_sig, 
            time_elapsed_gm17_comp_ver, 
            time_elapsed_gm17_opti_sig, 
            time_elapsed_gm17_opti_ver
            ])?;
        }
        
        writer.flush()?;
        
        println!("###############Benchmark of signature and session authentication finished###############");
        
        Ok(())
    }