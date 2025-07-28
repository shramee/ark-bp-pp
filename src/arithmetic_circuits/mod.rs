mod commit;
mod inner_circuit;
mod utils;

use crate::transcript::new_transcript;
use ark_ec::{CurveGroup, PrimeGroup};
pub use utils::*;

/// Impl ArithmeticCircuit for CurveGroup with BaseField
impl<G> ArithmeticCircuit<G::ScalarField, G>
where
    G: CurveGroup + PrimeGroup,
{
    pub fn prover_setup(
        &self,
        w_o: &Vec<G::ScalarField>,
        w_l: &Vec<G::ScalarField>,
        w_r: &Vec<G::ScalarField>,
        f: LayoutMapFn,
    ) {
        // 1. P computes:
        // r_O, r_L, n_O, n_L, l_O, l_L, C_O, C_L := CommitOL(w_O, w_L, F)
        // r_R, n_R, l_R, C_R := CommitR(w_O, w_R, F)
        let (r_o, r_l, n_o, n_l, l_o, l_l, c_o, c_l) = self.commit_ol(w_o, w_l, &f);
        let (r_r, n_r, l_r, c_r) = self.commit_r(w_o, w_r, &f);

        // 2. P, V run inner arithmetic circuit protocol
        let mut transcript = new_transcript(b"");
        self.inner_circuit_prover(
            r_o,
            r_l,
            r_r,
            n_o,
            n_l,
            n_r,
            l_o,
            l_l,
            l_r,
            c_o,
            c_l,
            c_r,
            &mut transcript,
        );
    }
}
