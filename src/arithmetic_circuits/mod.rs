mod commit;
mod inner_circuit;
mod utils;

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
        let (r_o, r_l, n_o, n_l, l_o, l_l, c_o, c_l) = self.commit_ol(w_o, w_l, &f);
        let (r_r, n_r, l_r, c_r) = self.commit_r(w_o, w_r, &f);
        // Do something with the commitments
    }
}
