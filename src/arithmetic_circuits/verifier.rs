pub use super::types::*;
use ark_ec::CurveGroup;
use ark_ff::Field;
use merlin::Transcript;

use crate::{
    transcript,
    util::*,
    wnla::{self, WeightNormLinearArgument},
};

impl<'a, C, P> ArithmeticCircuit<'a, C, P>
where
    C: CurveGroup,
    P: Fn(PartitionType, usize) -> Option<usize> + 'a,
{
    /// Verifies arithmetic circuit proof with respect to the `v` commitments vector.
    pub fn verify(&self, v: &[C], t: &mut Transcript, proof: Proof<C>) -> bool {
        transcript::app_point(b"commitment_cl", &proof.c_l, t);
        transcript::app_point(b"commitment_cr", &proof.c_r, t);
        transcript::app_point(b"commitment_co", &proof.c_o, t);

        v.iter()
            .for_each(|v_val| transcript::app_point(b"commitment_v", v_val, t));

        let rho = transcript::get_challenge::<C::ScalarField>(b"circuit_rho", t);
        let lambda = transcript::get_challenge::<C::ScalarField>(b"circuit_lambda", t);
        let beta = transcript::get_challenge::<C::ScalarField>(b"circuit_beta", t);
        let delta = transcript::get_challenge::<C::ScalarField>(b"circuit_delta", t);

        let mu = rho * rho;

        let lambda_vec = self.collect_lambda(&lambda, &mu);
        let mu_vec = vector_mul_on_scalar(&e(&mu, self.dim_nm), &mu);

        let (c_nL, c_nR, c_nO, c_lL, c_lR, c_lO) = self.collect_c(&lambda_vec, &mu_vec, &mu);

        let two = C::ScalarField::from(2u32);

        let mut v_ = C::zero();
        for i in 0..self.k {
            v_ += v[i] * self.linear_comb_coef(i, &lambda, &mu);
        }
        v_ = v_ * two;

        transcript::app_point(b"commitment_cs", &proof.c_s, t);

        let tau = transcript::get_challenge::<C::ScalarField>(b"circuit_tau", t);
        let tau_inv = tau.inverse().unwrap();
        let tau2 = tau * tau;
        let tau3 = tau2 * tau;
        let delta_inv = delta.inverse().unwrap();

        let mut pn_tau = vector_mul_on_scalar(&c_nO, &(tau3 * delta_inv));
        pn_tau = vector_sub(&pn_tau, &vector_mul_on_scalar(&c_nL, &tau2));
        pn_tau = vector_add(&pn_tau, &vector_mul_on_scalar(&c_nR, &tau));

        let ps_tau = weight_vector_mul(&pn_tau, &pn_tau, &mu)
            + vector_mul(&lambda_vec, &self.a_l) * tau3 * two
            - vector_mul(&mu_vec, &self.a_m) * tau3 * two;

        let pt = self.g * ps_tau + vector_mul(&self.g_vec, &pn_tau);

        let cr_tau = vec![
            C::ScalarField::ONE,
            tau_inv * beta,
            tau * beta,
            tau2 * beta,
            tau3 * beta,
            tau * tau3 * beta,
            tau2 * tau3 * beta,
            tau3 * tau3 * beta,
            tau3 * tau3 * tau * beta,
        ];

        let c_l0 = self.collect_cl0(&lambda, &mu);

        let mut cl_tau = vector_mul_on_scalar(&c_lO, &(tau3 * delta_inv));
        cl_tau = vector_sub(&cl_tau, &vector_mul_on_scalar(&c_lL, &tau2));
        cl_tau = vector_add(&cl_tau, &vector_mul_on_scalar(&c_lR, &tau));
        cl_tau = vector_mul_on_scalar(&cl_tau, &two);
        cl_tau = vector_sub(&cl_tau, &c_l0);

        let mut c = [&cr_tau[..], &cl_tau[..]].concat();

        let commitment = pt + proof.c_s * tau_inv - proof.c_o * delta + proof.c_l * tau
            - proof.c_r * tau2
            + v_ * tau3;

        // Pad c to the h/h_ vector size
        while c.len() < self.h_vec.len() + self.h_vec_.len() {
            c.push(C::ScalarField::default());
        }

        let wnla = WeightNormLinearArgument {
            g: self.g,
            g_vec: [&self.g_vec[..], &self.g_vec_[..]].concat(),
            h_vec: [&self.h_vec[..], &self.h_vec_[..]].concat(),
            c,
            rho,
            mu,
        };

        wnla.verify(
            &commitment,
            t,
            wnla::Proof {
                r: proof.r,
                x: proof.x,
                l: proof.l,
                n: proof.n,
            },
        )
    }
}
