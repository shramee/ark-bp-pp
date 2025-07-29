//! # Bulletproofs on Ark Algebra
//!
//! This crate provides an implementation of Bulletproofs zero-knowledge range proofs
//! using the Arkworks algebra libraries.
//!
//! Bulletproofs are short non-interactive zero-knowledge arguments of knowledge
//! that do not require a trusted setup. They can be used to convince a verifier
//! that a committed value lies in a given range, without revealing the value itself.

pub mod transcript;
pub mod util;

pub use transcript::*;
pub use util::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
