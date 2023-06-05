use std::error::Error;
use wake_implementation::benchmarks::benchmarking::{benchmark_sizes, benchmark_protocol, benchmark_signature_and_session_authentication};

#[cfg(not(tarpaulin_include))]
fn main() -> Result<(), Box<dyn Error>> {
    let protocol_sample_size = 2;
    let sign_and_session_auth_sample_size = 10;
    let party_amounts = vec![2, 3];

    let _ = benchmark_sizes();
    let _ = benchmark_protocol(protocol_sample_size, &party_amounts)?;
    let _ = benchmark_signature_and_session_authentication(sign_and_session_auth_sample_size)?;

    Ok(())
}