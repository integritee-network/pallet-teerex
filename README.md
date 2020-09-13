# pallet-substratee-registry

![badge](https://img.shields.io/badge/substrate-2.0.0--rc5-success)

A pallet for [SubstraTEE](https://www.substratee.com) that acts as a registry for SGX enclaves. 
The pallet verifies remote attestation quotes from Intel Attestation Services against theit root Certificate.

The pallet also acts as an indirect-invocation proxy for calls to the confidential state transition function
