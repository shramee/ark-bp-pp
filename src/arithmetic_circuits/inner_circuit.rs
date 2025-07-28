use crate::transcript::{app_scalars, get_challenge, Transcript};
use ark_ec::{CurveGroup, PrimeGroup};

use crate::arithmetic_circuits::ArithmeticCircuit;

/// Impl ArithmeticCircuit for CurveGroup with BaseField
impl<G> ArithmeticCircuit<G::ScalarField, G>
where
    G: CurveGroup + PrimeGroup,
{
    pub fn inner_circuit_prover(
        &self,
        r_o: [G::ScalarField; 8],
        r_l: [G::ScalarField; 8],
        r_r: [G::ScalarField; 8],
        n_o: Vec<G::ScalarField>,
        n_l: Vec<G::ScalarField>,
        n_r: Vec<G::ScalarField>,
        l_o: Vec<G::ScalarField>,
        l_l: Vec<G::ScalarField>,
        l_r: Vec<G::ScalarField>,
        c_o: G::ScalarField,
        c_l: G::ScalarField,
        c_r: G::ScalarField,
        transcript: &mut Transcript,
    ) {
        // 1. P -> V: CL, CR, CO
        app_scalars(b"commitments", &[c_l, c_r, c_o], transcript);

        // 2. V -> P: ρ, λ, β, δ ∈ F
        let rho: G::ScalarField = get_challenge(b"rho", transcript);
        let lambda: G::ScalarField = get_challenge(b"lambda", transcript);
        let beta: G::ScalarField = get_challenge(b"beta", transcript);
        let delta: G::ScalarField = get_challenge(b"delta", transcript);

        //
        todo!()
    }
}
