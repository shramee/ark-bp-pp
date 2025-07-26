# BulletProofs++ with arkworks::algebra

A high-performance implementation of BulletProofs++ built on the [`arkworks`](https://github.com/arkworks-rs) libraries, designed for seamless integration with any elliptic curve of your choice. This library delivers exceptionally efficient, compact zero-knowledge proofs for small circuits that can be deployed across multiple blockchain environments.

## Overview

BulletProofs++ via reciprocal set membership arguments, offers significant improvements over traditional Bulletproofs (and BulletProofs+) in both proof size and verification efficiency. BP++ retains all features of Bulletproofs including transparent setup and support for proof aggregation, multi-party proving and batch verification.

## Architecture
Our implementation leverages the robust [`ark-ec`](https://github.com/arkworks-rs/algebra) generic framework, ensuring maximum flexibility and performance across different cryptographic curves:

* Universal Curve Support: Built on Arkworks generics, enabling deployment on any supported elliptic curve
* Cross-Chain Compatibility: Same ZK circuits and proof generation backend work across different blockchains
* secp256k1 Ready: BP++ neither requires pairings nor cycles of curves and can be instantiated on the secp256k1 elliptic curve which used in Bitcoin
* Test/Examples with StarkCurve: For efficient runs Starknet (based chains)
* Test/Examples with secp256k: For efficient runs on EVM chain

### Reading materials

* [EKRN23 - BulletProofs++ ePrint - rev 2023](papers/2022-510-bulletproofs-plus-plus.pdf) - The foundational academic paper introducing BulletProofs++
* [FS24 - Bulletproofs++ Construction and Examples - Distributed Labs](papers/bulletproofs-plus-plus-construction-and-examples.pdf) - Practical construction guide with detailed examples
* [BP++ Scratch Pad - Sanket Kanjalkar (probably)](papers/bulletproofs-plus-plus-scratch-pad.pdf) - Technical implementation notes and insights
* [Bulletproofs++ review - Cypher Stack](papers/bulletproofs-plus-plus-review.pdf) - Comprehensive analysis and review of the protocol