mod commit;
mod inner_circuit;
mod utils;

use ark_ec::CurveGroup;
pub use utils::*;

/// Impl ArithmeticCircuit for CurveGroup with BaseField
impl<G> ArithmeticCircuit<G::BaseField, G>
where
    G: CurveGroup,
{
    // todo
}
