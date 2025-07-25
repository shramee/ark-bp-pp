//! Generalized Bulletproofs++ Weight Norm Linear Argument for any ark-ec curve
//!
//! This implementation provides a curve-agnostic version of the Weight Norm Linear Argument (WNLA)
//! protocol from Bulletproofs++. It works with any elliptic curve supported by the ark-ec library.

use ark_ec::CurveGroup;
use ark_ff::{Field, One};
use ark_std::{ops::Sub, vec, vec::Vec};

use crate::transcript;
use crate::util::*;

use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul};

/// Represents public information for the Weight Norm Linear Argument protocol.
///
/// The WNLA proves knowledge of vectors `l` and `n` such that:
/// `C = v*g + <l, h_vec> + <n, g_vec>` where `v = <c, l> + |n|²_μ`
#[derive(Clone, Debug)]
pub struct WeightNormLinearArgument<G: CurveGroup> {
    /// Generator point G ∈ G
    pub g: G,
    /// Vector of generator points G ∈ G^n
    pub g_vec: Vec<G>,
    /// Vector of generator points H ∈ G^l  
    pub h_vec: Vec<G>,
    /// Public coefficient vector c ∈ F^l
    pub c: Vec<G::ScalarField>,
    /// Challenge parameter ρ
    pub rho: G::ScalarField,
    /// Weight parameter μ
    pub mu: G::ScalarField,
}

/// Represents a Weight Norm Linear Argument proof.
///
/// Contains the recursive proof data generated during the proving process.
/// - `r` and `x` are intermediate commitments from the recursive reduction
/// - `l` and `n` are the final reduced vectors (when recursion terminates)
#[derive(Clone, Debug)]
pub struct Proof<G: CurveGroup> {
    /// Vector of R commitments from recursive reduction
    pub r: Vec<G>,
    /// Vector of X commitments from recursive reduction
    pub x: Vec<G>,
    /// Final l vector (when |l| + |n| < 6)
    pub l: Vec<G::ScalarField>,
    /// Final n vector (when |l| + |n| < 6)
    pub n: Vec<G::ScalarField>,
}

/// Serializable version of the WNLA proof using affine coordinates.
///
/// This version uses affine point representations for efficient serialization,
/// as affine points have a more compact encoding than projective points.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SerializableProof<G: CurveGroup>
where
    G::Affine: Serialize + for<'da> Deserialize<'da>,
    G::ScalarField: Serialize + for<'ds> Deserialize<'ds>,
{
    /// Vector of R commitments in affine coordinates
    pub r: Vec<G::Affine>,
    /// Vector of X commitments in affine coordinates
    pub x: Vec<G::Affine>,
    /// Final l vector
    pub l: Vec<G::ScalarField>,
    /// Final n vector
    pub n: Vec<G::ScalarField>,
}

/// Conversion from serializable proof to working proof
impl<G: CurveGroup> From<&SerializableProof<G>> for Proof<G>
where
    G::Affine: Serialize + for<'de> Deserialize<'de>,
    G::ScalarField: Serialize + for<'de> Deserialize<'de>,
{
    fn from(value: &SerializableProof<G>) -> Self {
        Proof {
            r: value
                .r
                .iter()
                .map(|r_val| G::from(*r_val))
                .collect::<Vec<_>>(),
            x: value
                .x
                .iter()
                .map(|x_val| G::from(*x_val))
                .collect::<Vec<_>>(),
            l: value.l.clone(),
            n: value.n.clone(),
        }
    }
}

/// Conversion from working proof to serializable proof
impl<G: CurveGroup> From<&Proof<G>> for SerializableProof<G>
where
    G::Affine: Serialize + for<'de> Deserialize<'de>,
    G::ScalarField: Serialize + for<'de> Deserialize<'de>,
{
    fn from(value: &Proof<G>) -> Self {
        SerializableProof {
            r: value
                .r
                .iter()
                .map(|r_val| r_val.into_affine())
                .collect::<Vec<_>>(),
            x: value
                .x
                .iter()
                .map(|x_val| x_val.into_affine())
                .collect::<Vec<_>>(),
            l: value.l.clone(),
            n: value.n.clone(),
        }
    }
}

impl<G: CurveGroup> WeightNormLinearArgument<G> {
    /// Creates a Weight Norm Linear Argument commitment to vectors `l` and `n`.
    ///
    /// Computes: `C = v*G + <l, H> + <n, G>` where `v = <c, l> + |n|²_μ`
    ///
    /// # Arguments
    /// * `l` - Secret vector l ∈ F^l
    /// * `n` - Secret vector n ∈ F^n
    ///
    /// # Returns
    /// Commitment point C ∈ G
    pub fn commit(&self, l: &[G::ScalarField], n: &[G::ScalarField]) -> G {
        // Compute v = <c, l> + |n|²_μ
        let v = vector_mul(&self.c, l).add(weight_vector_mul(n, n, &self.mu));

        // Compute C = v*G + <l, H> + <n, G>
        self.g
            .mul(v)
            .add(vector_mul(&self.h_vec, l))
            .add(vector_mul(&self.g_vec, n))
    }

    /// Verifies a Weight Norm Linear Argument proof for the provided commitment.
    ///
    /// Uses recursive verification with vector reduction until the base case is reached.
    ///
    /// # Arguments  
    /// * `commitment` - The commitment C to verify against
    /// * `t` - Fiat-Shamir transcript for challenge generation
    /// * `proof` - The WNLA proof to verify
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify(&self, commitment: &G, t: &mut Transcript, proof: Proof<G>) -> bool {
        // Check proof structure consistency
        if proof.x.len() != proof.r.len() {
            return false;
        }

        // Base case: no more recursive commitments, verify directly
        if proof.x.is_empty() {
            return commitment.eq(&self.commit(&proof.l, &proof.n));
        }

        // Recursive case: perform vector reduction

        // Split vectors into even/odd components
        let (c0, c1) = reduce(&self.c);
        let (g0, g1) = reduce(&self.g_vec);
        let (h0, h1) = reduce(&self.h_vec);

        // Update transcript with current proof elements
        transcript::app_point(b"wnla_com", commitment, t);
        transcript::app_point(b"wnla_x", proof.x.last().unwrap(), t);
        transcript::app_point(b"wnla_r", proof.r.last().unwrap(), t);
        t.append_u64(b"l.sz", self.h_vec.len() as u64);
        t.append_u64(b"n.sz", self.g_vec.len() as u64);

        // Generate challenge from transcript
        let y = transcript::get_challenge::<G>(b"wnla_challenge", t);

        // Compute reduced vectors
        let h_ = vector_add(&h0, &vector_mul_on_scalar(&h1, &y));
        let g_ = vector_add(
            &vector_mul_on_scalar(&g0, &self.rho),
            &vector_mul_on_scalar(&g1, &y),
        );
        let c_ = vector_add(&c0, &vector_mul_on_scalar(&c1, &y));

        // Compute reduced commitment
        let com_ = commitment.add(&proof.x.last().unwrap().mul(y)).add(
            &proof
                .r
                .last()
                .unwrap()
                .mul(y.mul(y).sub(G::ScalarField::one())),
        );

        // Create reduced WNLA instance
        let wnla = WeightNormLinearArgument {
            g: self.g,
            g_vec: g_,
            h_vec: h_,
            c: c_,
            rho: self.mu,
            mu: self.mu.mul(self.mu),
        };

        // Create reduced proof (remove last elements)
        let proof_ = Proof {
            r: proof.r[..proof.r.len() - 1].to_vec(),
            x: proof.x[..proof.x.len() - 1].to_vec(),
            l: proof.l,
            n: proof.n,
        };

        // Recursively verify reduced proof
        wnla.verify(&com_, t, proof_)
    }

    /// Creates a Weight Norm Linear Argument proof.
    ///
    /// Uses recursive proving with vector reduction until the base case is reached.
    ///
    /// # Arguments
    /// * `commitment` - The commitment C that corresponds to l and n
    /// * `t` - Fiat-Shamir transcript for challenge generation  
    /// * `l` - Secret vector l ∈ F^l
    /// * `n` - Secret vector n ∈ F^n
    ///
    /// # Returns
    /// WNLA proof for the given vectors
    pub fn prove(
        &self,
        commitment: &G,
        t: &mut Transcript,
        l: Vec<G::ScalarField>,
        n: Vec<G::ScalarField>,
    ) -> Proof<G> {
        // Base case: vectors are small enough, return directly
        if l.len() + n.len() < 6 {
            return Proof {
                r: vec![],
                x: vec![],
                l,
                n,
            };
        }

        // Recursive case: perform vector reduction

        // Compute ρ^(-1) for vector reduction
        let rho_inv = self.rho.inverse().unwrap();

        // Split all vectors into even/odd components
        let (c0, c1) = reduce(&self.c);
        let (l0, l1) = reduce(&l);
        let (n0, n1) = reduce(&n);
        let (g0, g1) = reduce(&self.g_vec);
        let (h0, h1) = reduce(&self.h_vec);

        // Compute μ² for next iteration
        let mu2 = self.mu.mul(self.mu);

        // Compute intermediate values for commitments X and R
        let vx = weight_vector_mul(&n0, &n1, &mu2)
            .mul(rho_inv.mul(G::ScalarField::from(2u32)))
            .add(vector_mul(&c0, &l1))
            .add(vector_mul(&c1, &l0));

        let vr = weight_vector_mul(&n1, &n1, &mu2).add(vector_mul(&c1, &l1));

        // Compute commitment X
        let x = self
            .g
            .mul(vx)
            .add(vector_mul(&h0, &l1))
            .add(vector_mul(&h1, &l0))
            .add(vector_mul(&g0, &vector_mul_on_scalar(&n1, &self.rho)))
            .add(vector_mul(&g1, &vector_mul_on_scalar(&n0, &rho_inv)));

        // Compute commitment R
        let r = self
            .g
            .mul(vr)
            .add(vector_mul(&h1, &l1))
            .add(vector_mul(&g1, &n1));

        // Update transcript with current commitments
        transcript::app_point(b"wnla_com", commitment, t);
        transcript::app_point(b"wnla_x", &x, t);
        transcript::app_point(b"wnla_r", &r, t);
        t.append_u64(b"l.sz", l.len() as u64);
        t.append_u64(b"n.sz", n.len() as u64);

        // Generate challenge from transcript
        let y = transcript::get_challenge::<G>(b"wnla_challenge", t);

        // Compute reduced vectors
        let h_ = vector_add(&h0, &vector_mul_on_scalar(&h1, &y));
        let g_ = vector_add(
            &vector_mul_on_scalar(&g0, &self.rho),
            &vector_mul_on_scalar(&g1, &y),
        );
        let c_ = vector_add(&c0, &vector_mul_on_scalar(&c1, &y));

        // Reduce witness vectors
        let l_ = vector_add(&l0, &vector_mul_on_scalar(&l1, &y));
        let n_ = vector_add(
            &vector_mul_on_scalar(&n0, &rho_inv),
            &vector_mul_on_scalar(&n1, &y),
        );

        // Create reduced WNLA instance for recursion
        let wnla = WeightNormLinearArgument {
            g: self.g,
            g_vec: g_,
            h_vec: h_,
            c: c_,
            rho: self.mu,
            mu: mu2,
        };

        // Recursively prove reduced instance
        let mut proof = wnla.prove(&wnla.commit(&l_, &n_), t, l_, n_);

        // Add current level commitments to proof
        proof.r.push(r);
        proof.x.push(x);

        proof
    }
}
