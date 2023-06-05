# Wake Implementation
This project implements the two different [WAKE](https://eprint.iacr.org/2022/382) protocols over the Dark Pool Transaction relation. 

## Protocols
We implement WAKE using two different proof-systems, namely [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf) and the [GM17](https://eprint.iacr.org/2017/540.pdf) SE zk-SNARK. This gives us four different combinations, given the two WAKE protocols, and the 2 different underlying proof-types. The two compiler versions are thus:
* Compiler WAKE using Bulletproofs: located [here](src/protocols/compiler_bp_wake/)
* Compiler WAKE using GM17: located [here](src/protocols/compiler_gm17_wake/)

Both of these solutions have the same base structure with a protocol file (**compiler_bp_wake_protocol.rs** and **compiler_gm17_wake_protocol.rs**) holding the public function **run_compiler_key_exchange**. They also both have signature files (**compiler_bp_wake_signature.rs** and **compiler_gm17_wake_signature.rs**), which are used inside the protocol files. 

Likewise, we have two 2-round optimized WAKE protocols:
* Optimized WAKE using Bulletproofs: located [here](src/protocols/optimized_bp_wake/)
* Optimized WAKE using GM17: located [here](src/protocols/optimized_gm17_wake/)

These modules have the same basic structure as the compiler versions. The public functions are named **run_optimized_key_exchange** in the protocol files (**optimized_bp_wake_protocol.rs** and **optimized_gm17_wake_protocol.rs**), and they do not have pure signature files, but they are extended with session authentication (**optimized_bp_wake_signature_and_session_authentication.rs** and **optimized_gm17_wake_signature_and_session_authentication.rs**)

## Proof-systems
In [proof_systems](src/proof_systems/) we have bundled the underlying proof systems: [Bulletproof range-proof](src/proof_systems/range_proof.rs), [GM17](src/proof_systems/proof_system_gm17.rs) and the [discrete logarithm knowledge proof](src/proof_systems/discrete_log_knowledege_proof.rs) used for session authentication of the optimized WAKE protocol.

## Utility
General utility functions are found in [here](src/utility.rs).

## Benchmarking
Benchmarking of the 4 protocols is dictated by the [benchmarks](src/benchmarks/) module, with the benchmarking functions residing in [here](src/benchmarks/benchmarking.rs). These test protocol running time between the aforementioned protocols, as well as compare them to the vanilla underlying key-exchange protocol (Burmester-Desmedt). Another benchmarking function tests the proving- and verification times of our signature and signature_and_session_authentication files. The [main.rs](src/main.rs) file is configured to run benchmarking with the specified party-amount and sample-size.

## Tests
In the [tests](tests) folder are found [proof_system tests](tests/proof_systems/) for testing the [proof_system module](src/proof_systems/), and likewise [protocol tests](tests/protocols/) for testing the [protocols module](src/protocols/).
- - -
## Requirements
* Rust compiler: The executions of tests and benchmarking was performed on Rust compiler version "rustc 1.69.0"
* Cargo (package manager): The execution of tests and benchmarking was performed on Cargo version "cargo 1.69.0"
* Python interpreter: The plotting executions were performed using Python version "Python 3.10.6"

- - -
## How to run:
There are two main functionalities of this repo:
* Running tests
* Performing benchmarking

To ensure that these run, ensure the [requirements](#requirements) are met on your machine.

**Tests:**

To run tests ensure terminal at root of the project. Then type the following command:
```
cargo test
```

**Benchmarking**

To run the benchmarking, merely run the **main.rs** file as follows:
```
cargo run
```
This produces 3 different data files output [here](src/benchmarks/data/). By running the 3 python scripts, plots are produced inside of [here](src/benchmarks/plots/). To do this, insert on of the following three terminal commands (from the root of the project):
```
python3 src/benchmarks/plotting_protocol.py
```
```
python3 src/benchmarks/plotting_sign_and_session_auth_and_verification.py
```
```
python3 src/benchmarks/plotting_sizes.py
```
Alternatively execute the following to run all the above 3 in succession:
```
python3 src/benchmarks/plotting_all.py
```