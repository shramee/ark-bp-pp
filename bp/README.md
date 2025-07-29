# Bulletproofs on Ark Algebra

This crate provides an implementation of Bulletproofs zero-knowledge range proofs using the Arkworks algebra libraries.

## Overview

Bulletproofs are short non-interactive zero-knowledge arguments of knowledge that do not require a trusted setup. They can be used to convince a verifier that a committed value lies in a given range, without revealing the value itself.

## Features

- Efficient range proofs
- No trusted setup required
- Compatible with Arkworks ecosystem
- Transcript-based Fiat-Shamir transform

## Usage

```rust
use ark_bp::{TranscriptProtocol, inner_product, powers};
use merlin::Transcript;

// Example usage will be added as the implementation develops
```

## Development

This crate is part of a workspace that also includes `ark-bp-pp` (Bulletproofs++).

### Running Tests

```bash
cargo test
```

### Running Benchmarks

```bash
cargo bench
```

## License

MIT
