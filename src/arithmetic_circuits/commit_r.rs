use ark_ff::Field;
use ark_std::{
    ops::{Add, Mul, Sub},
    vec::Vec,
};

use crate::{arithmetic_circuits::utils::LayoutMapFn, util::sample_random_vector};

/// CommitR Subroutine  
/// Creates commitment for the right (R) witness vector[1]
/// **Input**: `wO` (output witness), `wR` (right witness), `F` (layout function)
/// **Process**:
/// 1. Generate random blinding factors `r'_R ∈ F^4`
/// 2. Construct blinding vector: `rR := (r'_R,0, r'_R,1, 0, r'_R,2, r'_R,3, 0, 0, 0) ∈ F^8`
/// 3. Set `nR := wR ∈ F^Nm` (norm component from right witness)
/// 4. Map output witness to linear component: `lR,j := wO,i if F^-1(lR, j) = i, else 0`
/// 5. Compute commitment: `CR := rR,0*G + ⟨rR,1:||lR, H⟩ + ⟨nR, G⟩`

fn commit_r<F>(w_o: Vec<F>, w_r: Vec<F>, f: LayoutMapFn) -> (Vec<F>, Vec<F>, Vec<F>, F)
where
    // T: Copy + Default + for<'a> Mul<&'a F, Output = T> + Add<Output = T>,
    F: Field,
{
    // Sample r'_R ∈ F^4
    let r_dash_r = sample_random_vector::<F>(4);

    // r_R := (r'_R,0, r'_R,1, 0, r'_R,2, r'_R,3, 0, 0, 0) ∈ F^8
    let r_r = r_dash_r
        .into_iter()
        .chain(std::iter::repeat(F::zero()).take(4))
        .collect::<Vec<F>>();

    // `nR := wR ∈ F^Nm
    let n_r = w_r; // Norm component from right witness

    // Map output witness to linear component: `lR,j := wO,i if F^-1(lR, j) = i, else 0`
    let l_r: Vec<F> = f
        .iter()
        .map(|(_, loc)| match loc {
            WitnessLocation::LO(i) => w_o[i],
            _ => F::zero(),
        })
        .collect();

    // Compute commitment CR
    let c_r = r_r[0] * G + r_r[1] * l_r + n_r * G; // Assuming G is a generator point

    (r_r, n_r, l_r, c_r)
}
