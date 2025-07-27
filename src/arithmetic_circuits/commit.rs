use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::Field;
use ark_std::{
    ops::{Add, Mul, Sub},
    vec::Vec,
};

use crate::{
    arithmetic_circuits::{
        utils::{LayoutMapFn, WitnessLocation},
        ArithmeticCircuit,
    },
    util::sample_random_vector,
    vector_mul,
};

impl<G> ArithmeticCircuit<G::ScalarField, G>
where
    G: CurveGroup + PrimeGroup,
{
    /// CommitR Subroutine  
    /// Creates commitment for the right (R) witness vector[1]
    /// **Input**: `wO` (output witness), `wR` (right witness), `F` (layout function)
    /// **Process**:
    /// 1. Generate random blinding factors `r'R ∈ F^4`
    /// 2. Construct blinding vector: `rR := (r'R[0], r'R[1], 0, r'R[2], r'R[3], 0, 0, 0) ∈ F^8`
    /// 3. Set `nR := wR ∈ F^Nm` (norm component from right witness)
    /// 4. Map output witness to linear component: `lR,j := wO,i if F^-1(lR, j) = i, else 0`
    /// 5. Compute commitment: `CR := rR,0*G + ⟨rR,1:||lR, H⟩ + ⟨nR, G⟩`
    pub fn commit_r(
        self,
        w_o: Vec<G::ScalarField>,
        w_r: Vec<G::ScalarField>,
        f: LayoutMapFn,
    ) -> (
        [G::ScalarField; 8],
        Vec<G::ScalarField>,
        Vec<G::ScalarField>,
        G::ScalarField,
    ) {
        // Sample r'R ∈ F^4
        let [r_r0, r_r1, r_r2, r_r3] = sample_random_vector::<G::ScalarField, 4>();

        // init zero field element to fill zero positions
        let f0 = G::ScalarField::default();

        // rR := (r'R[0], r'R[1], 0, r'R[2], r'R[3], 0, 0, 0) ∈ F^8
        let r_r = [r_r0, r_r1, f0, r_r2, r_r3, f0, f0, f0];

        // `nR := wR ∈ F^Nm
        let n_r = w_r.clone(); // Norm component from right witness

        // Map output witness to linear component: `lR,j := wO,i if F^-1(lR, j) = i, else 0`
        // Not super sure this is how it should work
        let l_r: Vec<G::ScalarField> = f
            .iter()
            .map(|(_, loc)| match loc {
                WitnessLocation::LO(i) => w_o[*i],
                _ => G::ScalarField::default(),
            })
            .collect();

        // CR := rR,0*G + ⟨rR,1:||lR, H⟩ + ⟨nR, G⟩
        let c_r = r_r[0] * self.g
            + vector_mul(&[&r_r[1..], &l_r[..]].concat(), &self.h_vec)
            + vector_mul(&n_r, &self.g_vec); // Assuming g is a generator point

        (r_r, n_r, l_r, c_r)
    }
}
