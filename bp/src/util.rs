//! Utility functions and types for Bulletproofs

use ark_ff::PrimeField;
use ark_ec::CurveGroup;
use ark_std::vec::Vec;

/// Compute the inner product of two vectors
pub fn inner_product<F: PrimeField>(a: &[F], b: &[F]) -> F {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(ai, bi)| *ai * bi).sum()
}

/// Compute a multi-scalar multiplication
pub fn multiscalar_mul<G: CurveGroup>(scalars: &[G::ScalarField], points: &[G]) -> G {
    assert_eq!(scalars.len(), points.len());
    scalars
        .iter()
        .zip(points.iter())
        .map(|(s, p)| *p * s)
        .sum()
}

/// Generate powers of a scalar: [1, x, x^2, ..., x^(n-1)]
pub fn powers<F: PrimeField>(x: F, n: usize) -> Vec<F> {
    let mut powers = Vec::with_capacity(n);
    let mut current = F::one();
    for _ in 0..n {
        powers.push(current);
        current *= x;
    }
    powers
}

/// Hadamard product of two vectors (element-wise multiplication)
pub fn hadamard_product<F: PrimeField>(a: &[F], b: &[F]) -> Vec<F> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(ai, bi)| *ai * bi).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use ark_starkcurve::Fr;

    #[test]
    fn test_inner_product() {
        let a = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let b = vec![Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)];
        let result = inner_product(&a, &b);
        // 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
        assert_eq!(result, Fr::from(32u64));
    }

    #[test]
    fn test_powers() {
        let x = Fr::from(2u64);
        let powers = powers(x, 4);
        assert_eq!(powers, vec![Fr::from(1u64), Fr::from(2u64), Fr::from(4u64), Fr::from(8u64)]);
    }

    #[test]
    fn test_hadamard_product() {
        let a = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let b = vec![Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)];
        let result = hadamard_product(&a, &b);
        assert_eq!(result, vec![Fr::from(4u64), Fr::from(10u64), Fr::from(18u64)]);
    }
}
