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
    util::{sample_random_vector, vector_mul},
};

// The degree of freedom is how the vector wO is represented in the vectors (nO,lO,lL,lR)

impl<G> ArithmeticCircuit<G::ScalarField, G>
where
    G: CurveGroup + PrimeGroup,
{
    /// Creates a commitment for the output (O) and left (L) witness vectors.
    /// CX := rX,0*G + ⟨rX,1:||lX, H⟩ + ⟨nX, G⟩
    pub fn commitment(&self, w_x: &Vec<G::ScalarField>, r: &[G::ScalarField; 8]) -> G::ScalarField {
        let rnd_bar_l_x = [&r[1..], &w_x[..]].concat();
        r[0] * self.g + vector_mul(&rnd_bar_l_x, &self.h_vec) + vector_mul(w_x, &self.g_vec)
    }

    /// Map output witness `wO` to norm and linear components using layout function `F`
    /// @TODO: Not super sure this is how it should work
    pub fn witness_map(
        w_o: &Vec<G::ScalarField>,
        loc: WitnessLocation,
        f: &LayoutMapFn,
    ) -> Vec<G::ScalarField> {
        let f0 = G::ScalarField::default();
        f.iter()
            .map(|(i, l)| if &loc == l { w_o[*i] } else { f0 })
            .collect()
    }

    /// CommitR Subroutine
    /// Creates commitment for the right (R) witness vector[1]
    /// **Input**: `wO` (output witness), `wR` (right witness), `F` (layout function)
    /// **Process**:
    /// 1. Generate random blinding factors `r'R ∈ F^4`
    /// 2. Construct blinding vector: `rR := (r'R[0], r'R[1], 0, r'R[2], r'R[3], 0, 0, 0) ∈ F^8`
    /// 3. Set `nR := wR ∈ F^Nm` (norm component from right witness)
    /// 4. Output witness by type: `lR,j := wO,i if F^-1(lR, j) = i, else 0`
    /// 5. Compute commitment: `CR := rR,0*G + ⟨rR,1:||lR, H⟩ + ⟨nR, G⟩`
    pub fn commit_r(
        self,
        w_o: Vec<G::ScalarField>,
        w_r: Vec<G::ScalarField>,
        f: LayoutMapFn,
    ) -> (
        [G::ScalarField; 8], // r_R
        Vec<G::ScalarField>, // n_R
        Vec<G::ScalarField>, // l_R
        G::ScalarField,      // C_R
    ) {
        // Sample r'R ∈ F^4
        let [r_r0, r_r1, r_r2, r_r3] = sample_random_vector::<G::ScalarField, 4>();

        // init zero field element to fill zero positions
        let f0 = G::ScalarField::default();

        // rR := (r'R[0], r'R[1], 0, r'R[2], r'R[3], 0, 0, 0) ∈ F^8
        let r_r = [r_r0, r_r1, f0, r_r2, r_r3, f0, f0, f0];

        // `nR := wR ∈ F^Nm
        let n_r = w_r.clone(); // Norm component from right witness

        // lR,j := wO,i if F^-1(lR, j) = i, else 0
        let l_r = Self::witness_map(&w_o, WitnessLocation::LR, &f);

        // CR := rR,0*G + ⟨rR,1:||lR, H⟩ + ⟨nR, G⟩
        let c_r = self.commitment(&l_r, &r_r); // Assuming g is a generator point

        (r_r, n_r, l_r, c_r)
    }

    /// **Purpose**: Creates commitments for the output (O) and left (L) witness vectors[1]
    /// **Input**: `wO` (output witness), `wL` (left witness), `F` (layout function)
    /// **Process**:
    /// 1. Generate random blinding factors `r'_O ∈ F^6` and `r'_L ∈ F^5`
    /// 2. Construct blinding vectors:
    ///    - `rO := (r'_O[0], r'_O[1], r'_O[2], r'_O[3], 0, r'_O[4], r'_O[5], 0) ∈ F^8`
    ///    - `rL := (r'_L[0], r'_L[1], r'_L[2], 0, r'_L[3], r'_L[4], 0, 0) ∈ F^8`
    /// 3. Set `nL := wL ∈ F^Nm` (norm component from left witness)
    /// 4. Map output witness `wO` to norm and linear components using layout function `F`:
    ///    - `nO,j := wO,i if F^-1(nO, j) = i, else 0`
    ///    - `lX,j := wO,i if F^-1(lX, j) = i, else 0`
    ///    - `lX,j := wO,i if F^-1(lX, j) = i, else 0`
    /// 5. Compute commitments: `CX := rX,0*G + ⟨rX,1:||lX, H⟩ + ⟨nX, G⟩` for X = L, O
    pub fn commit_ol(
        self,
        w_o: Vec<G::ScalarField>,
        w_l: Vec<G::ScalarField>,
        f: LayoutMapFn,
    ) -> (
        [G::ScalarField; 8], // r_O
        [G::ScalarField; 8], // r_L
        Vec<G::ScalarField>, // n_O
        Vec<G::ScalarField>, // n_L
        Vec<G::ScalarField>, // l_O
        Vec<G::ScalarField>, // l_L
        G::ScalarField,      // C_O
        G::ScalarField,      // C_L
    ) {
        // r'_O ∈ F^6` and `r'_L ∈ F^5
        let [r_o0, r_o1, r_o2, r_o3, r_o4, r_o5] = sample_random_vector::<G::ScalarField, 6>();
        let [r_l0, r_l1, r_l2, r_l3, r_l4] = sample_random_vector::<G::ScalarField, 5>();

        // init zero field element to fill zero positions
        let f0 = G::ScalarField::default();

        // rO := (r'_O[0], r'_O[1], r'_O[2], r'_O[3], 0, r'_O[4], r'_O[5], 0) ∈ F^8
        let r_o = [r_o0, r_o1, r_o2, r_o3, f0, r_o4, r_o5, f0];
        // rL := (r'_L[0], r'_L[1], r'_L[2], 0, r'_L[3], r'_L[4], 0, 0) ∈ F^8
        let r_l = [r_l0, r_l1, r_l2, f0, r_l3, r_l4, f0, f0];

        // nL := wL ∈ F^Nm
        let n_l = w_l.clone();
        // nO,j := wO,i if F^-1(nO, j) = i, else 0
        let n_o = Self::witness_map(&w_o, WitnessLocation::NO, &f);

        // lO,j := wO,i if F^-1(lO, j) = i, else 0
        let l_o = Self::witness_map(&w_o, WitnessLocation::LO, &f);
        // lL,j := wO,i if F^-1(lL, j) = i, else 0
        let l_l = Self::witness_map(&w_o, WitnessLocation::LL, &f);

        // CL := rL,0*G + ⟨rL,1:||lL, H⟩ + ⟨nL, G⟩
        let c_l = self.commitment(&l_l, &r_l);
        // CO := rO,0*G + ⟨rO,1:||lO, H⟩ + ⟨nO, G⟩
        let c_o = self.commitment(&l_o, &r_o);

        (r_o, r_l, n_o, n_l, l_o, l_l, c_o, c_l)
    }
}
