//! Transcript utilities for Fiat-Shamir transform
//!
//! This module provides transcript functionality for implementing the Fiat-Shamir
//! transform in Bulletproofs, enabling non-interactive zero-knowledge proofs.

use merlin::Transcript;
use ark_ff::PrimeField;
use ark_ec::{CurveGroup, AffineRepr};
use ark_serialize::CanonicalSerialize;

/// Extension trait for Transcript to add domain-specific methods
pub trait TranscriptProtocol {
    /// Append a scalar field element to the transcript
    fn append_scalar<F: PrimeField>(&mut self, label: &'static [u8], scalar: &F);
    
    /// Append a group element to the transcript
    fn append_point<G: CurveGroup>(&mut self, label: &'static [u8], point: &G);
    
    /// Challenge a scalar from the transcript
    fn challenge_scalar<F: PrimeField>(&mut self, label: &'static [u8]) -> F;
}

impl TranscriptProtocol for Transcript {
    fn append_scalar<F: PrimeField>(&mut self, label: &'static [u8], scalar: &F) {
        let mut buf = Vec::new();
        scalar.serialize_compressed(&mut buf).unwrap();
        self.append_message(label, &buf);
    }
    
    fn append_point<G: CurveGroup>(&mut self, label: &'static [u8], point: &G) {
        let mut buf = Vec::new();
        point.into_affine().serialize_compressed(&mut buf).unwrap();
        self.append_message(label, &buf);
    }
    
    fn challenge_scalar<F: PrimeField>(&mut self, label: &'static [u8]) -> F {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        F::from_le_bytes_mod_order(&buf)
    }
}
