# pallet-teerex

A pallet for [Integritee](https://integritee.network) that acts as a registry for SGX enclaves. 
The pallet verifies remote attestation quotes from Intel Attestation Services against their root Certificate.

The pallet also acts as an indirect-invocation proxy for calls to the confidential state transition function

## Build

Install Rust:
```bash
curl https://sh.rustup.rs -sSf | sh
```

In order to compile *ring* into wasm, you'll need LLVM-9 or above or you'll get linker errors. Here the instructions for Ubuntu 18.04

```bash
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 10
export CC=/usr/bin/clang-10
export AR=/usr/bin/llvm-ar-10
# if you already built, make sure to run cargo clean
```

## Test

Run all unit tests with 

```
cargo test --all
```

