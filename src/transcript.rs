//! Generic transcript operations for Fiat-Shamir transform in Bulletproofs++
//!
//! This module provides curve-agnostic transcript operations for generating
//! cryptographic challenges using the Fiat-Shamir heuristic. It works with
//! any elliptic curve supported by ark-ec.

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use merlin::Transcript;

/// Appends an elliptic curve point to the transcript.
///
/// Serializes the point in a canonical way and adds it to the transcript.
/// This ensures that the same point always produces the same transcript state,
/// regardless of its internal representation (projective vs affine coordinates).
///
/// # Arguments
/// * `label` - Byte string label for domain separation
/// * `p` - Elliptic curve point to append
/// * `t` - Merlin transcript to append to
///
/// # Security Note
/// Uses canonical serialization to ensure consistent hashing across
/// different point representations and implementations.
pub fn app_point<G: CurveGroup>(label: &'static [u8], p: &G, t: &mut Transcript) {
    // Convert to affine coordinates for canonical representation
    let affine_point = p.into_affine();

    // Serialize the point canonically
    let mut bytes = Vec::new();
    affine_point
        .serialize_compressed(&mut bytes)
        .expect("Point serialization failed");

    // Append to transcript
    t.append_message(label, &bytes);
}

/// Generates a challenge scalar from the transcript.
///
/// Uses the Fiat-Shamir transform to generate a random challenge scalar
/// from the current transcript state. The challenge is uniformly distributed
/// in the scalar field.
///
/// # Arguments
/// * `label` - Byte string label for domain separation
/// * `t` - Merlin transcript to extract challenge from
///
/// # Returns
/// Random challenge scalar in the curve's scalar field
///
/// # Security Note
/// The challenge generation uses cryptographically secure randomness
/// derived from the transcript state, ensuring unpredictability.
pub fn get_challenge<G: CurveGroup>(label: &'static [u8], t: &mut Transcript) -> G::ScalarField
where
    G::ScalarField: PrimeField,
{
    // Get challenge bytes from transcript
    let mut buf = vec![0u8; 64]; // Use 64 bytes for better security margin
    t.challenge_bytes(label, &mut buf);

    // Convert bytes to field element using hash-to-field
    // This ensures uniform distribution in the scalar field
    G::ScalarField::from_be_bytes_mod_order(&buf)
}

/// Alternative implementation using a specific field size
///
/// Some curves may require specific byte sizes for optimal security.
/// This function allows specifying the exact number of challenge bytes.
pub fn get_challenge_with_size<G: CurveGroup>(
    label: &'static [u8],
    t: &mut Transcript,
    byte_size: usize,
) -> G::ScalarField
where
    G::ScalarField: PrimeField,
{
    let mut buf = vec![0u8; byte_size];
    t.challenge_bytes(label, &mut buf);
    G::ScalarField::from_be_bytes_mod_order(&buf)
}

/// Appends a scalar field element to the transcript.
///
/// Useful for building transcripts that include both points and scalars.
///
/// # Arguments
/// * `label` - Byte string label for domain separation
/// * `scalar` - Scalar field element to append
/// * `t` - Merlin transcript to append to
pub fn app_scalar<F: PrimeField>(label: &'static [u8], scalar: &F, t: &mut Transcript) {
    let mut bytes = Vec::new();
    scalar
        .serialize_compressed(&mut bytes)
        .expect("Scalar serialization failed");
    t.append_message(label, &bytes);
}

/// Appends multiple points to the transcript efficiently.
///
/// For batch operations where multiple points need to be added.
///
/// # Arguments
/// * `label` - Byte string label for domain separation
/// * `points` - Slice of points to append
/// * `t` - Merlin transcript to append to
pub fn app_points<G: CurveGroup>(label: &'static [u8], points: &[G], t: &mut Transcript) {
    for point in points.iter() {
        app_point(label, point, t);
    }
}

/// Appends multiple scalars to the transcript efficiently.
///
/// For batch operations where multiple scalars need to be added.
///
/// # Arguments
/// * `label` - Byte string label for domain separation  
/// * `scalars` - Slice of scalars to append
/// * `t` - Merlin transcript to append to
pub fn app_scalars<F: PrimeField>(label: &'static [u8], scalars: &[F], t: &mut Transcript) {
    for scalar in scalars.iter() {
        app_scalar(label, scalar, t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::G1Projective;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn test_transcript_consistency() {
        let mut rng = test_rng();
        let point = G1Projective::rand(&mut rng);

        // Test that same point produces same transcript state
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");

        app_point(b"point", &point, &mut t1);
        app_point(b"point", &point, &mut t2);

        let challenge1 = get_challenge::<G1Projective>(b"challenge", &mut t1);
        let challenge2 = get_challenge::<G1Projective>(b"challenge", &mut t2);

        assert_eq!(challenge1, challenge2);
    }

    #[test]
    fn test_different_points_different_challenges() {
        let mut rng = test_rng();
        let point1 = G1Projective::rand(&mut rng);
        let point2 = G1Projective::rand(&mut rng);

        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");

        app_point(b"point", &point1, &mut t1);
        app_point(b"point", &point2, &mut t2);

        let challenge1 = get_challenge::<G1Projective>(b"challenge", &mut t1);
        let challenge2 = get_challenge::<G1Projective>(b"challenge", &mut t2);

        assert_ne!(challenge1, challenge2);
    }
}
