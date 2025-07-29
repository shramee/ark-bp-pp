#![allow(non_snake_case)]

//! Definition and implementation of the Bulletproofs++ arithmetic circuit protocol.

use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::{
    rand::{CryptoRng, RngCore},
    vec::Vec,
};
use merlin::Transcript;

use crate::{
    transcript,
    util::*,
    wnla::{self, WeightNormLinearArgument},
};

#[derive(Clone, Debug, Copy, PartialEq)]
pub enum PartitionType {
    LO,
    LL,
    LR,
    NO,
}

/// Represents arithmetic circuit zero-knowledge proof.
#[derive(Clone, Debug)]
pub struct Proof<C: CurveGroup> {
    pub c_l: C,
    pub c_r: C,
    pub c_o: C,
    pub c_s: C,
    pub r: Vec<C>,
    pub x: Vec<C>,
    pub l: Vec<C::ScalarField>,
    pub n: Vec<C::ScalarField>,
}

/// Represent serializable version of arithmetic circuit proof (uses Affine instead of Projective).
#[derive(Clone, Debug)]
pub struct SerializableProof<C: CurveGroup> {
    pub c_l: C::Affine,
    pub c_r: C::Affine,
    pub c_o: C::Affine,
    pub c_s: C::Affine,
    pub r: Vec<C::Affine>,
    pub x: Vec<C::Affine>,
    pub l: Vec<C::ScalarField>,
    pub n: Vec<C::ScalarField>,
}

impl<C: CurveGroup> From<&SerializableProof<C>> for Proof<C> {
    fn from(value: &SerializableProof<C>) -> Self {
        Proof {
            c_l: value.c_l.into(),
            c_r: value.c_r.into(),
            c_o: value.c_o.into(),
            c_s: value.c_s.into(),
            r: value.r.iter().map(|p| (*p).into()).collect(),
            x: value.x.iter().map(|p| (*p).into()).collect(),
            l: value.l.clone(),
            n: value.n.clone(),
        }
    }
}

impl<C: CurveGroup> From<&Proof<C>> for SerializableProof<C> {
    fn from(value: &Proof<C>) -> Self {
        SerializableProof {
            c_l: value.c_l.into_affine(),
            c_r: value.c_r.into_affine(),
            c_o: value.c_o.into_affine(),
            c_s: value.c_s.into_affine(),
            r: value.r.iter().map(|r_val| r_val.into_affine()).collect(),
            x: value.x.iter().map(|x_val| x_val.into_affine()).collect(),
            l: value.l.clone(),
            n: value.n.clone(),
        }
    }
}

/// Represents arithmetic circuit witness.
#[derive(Clone, Debug)]
pub struct Witness<F: PrimeField> {
    /// Dimension: `k*dim_nv`
    pub v: Vec<Vec<F>>,
    /// Dimension: `k`
    pub s_v: Vec<F>,
    /// Dimension: `dim_nm`
    pub w_l: Vec<F>,
    /// Dimension: `dim_nm`
    pub w_r: Vec<F>,
    /// Dimension: `dim_no`
    pub w_o: Vec<F>,
}

/// Represents arithmetic circuit.
/// P - partition function.
pub struct ArithmeticCircuit<'a, C, P>
where
    C: CurveGroup,
    P: Fn(PartitionType, usize) -> Option<usize> + 'a,
{
    pub dim_nm: usize,
    pub dim_no: usize,
    pub k: usize,
    /// Equals to: `dim_nv * k`
    pub dim_nl: usize,
    /// Count of witness vectors v.
    pub dim_nv: usize,
    /// Equals to: `dim_nm + dim_nm + n_o`
    pub dim_nw: usize,
    pub g: C,
    /// Dimension: `dim_nm`
    pub g_vec: Vec<C>,
    /// Dimension: `dim_nv+9`
    pub h_vec: Vec<C>,
    /// Dimension: `dim_nm * dim_nw`
    pub W_m: Vec<Vec<C::ScalarField>>,
    /// Dimension: `dim_nl * dim_nw`
    pub W_l: Vec<Vec<C::ScalarField>>,
    /// Dimension: `dim_nm`
    pub a_m: Vec<C::ScalarField>,
    /// Dimension: `dim_nl`
    pub a_l: Vec<C::ScalarField>,
    pub f_l: bool,
    pub f_m: bool,
    /// Vector of points that will be used in WNLA protocol.
    /// Dimension: `2^n - dim_nm`
    pub g_vec_: Vec<C>,
    /// Vector of points that will be used in WNLA protocol.
    /// Dimension: `2^n - (dim_nv+9)`
    pub h_vec_: Vec<C>,
    /// Partition function to map `w_o` and corresponding parts of `W_m` and `W_l`
    pub partition: P,
    _phantom: std::marker::PhantomData<&'a ()>,
}

impl<'a, C, P> ArithmeticCircuit<'a, C, P>
where
    C: CurveGroup,
    P: Fn(PartitionType, usize) -> Option<usize> + 'a,
{
    /// Creates commitment to the arithmetic circuit witness.
    pub fn commit(&self, v: &[C::ScalarField], s: &C::ScalarField) -> C {
        self.g * v[0] + self.h_vec[0] * s + vector_mul(&self.h_vec[9..], &v[1..])
    }

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

    /// Creates arithmetic circuit proof for the corresponding witness. Also, `v` commitments vector
    /// should correspond input witness in `witness` argument.
    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        v: &[C],
        witness: Witness<C::ScalarField>,
        t: &mut Transcript,
        rng: &mut R,
    ) -> Proof<C> {
        // Randomizers for commitments
        let mut rand_scalars = || {
            (0..9)
                .map(|_| C::ScalarField::rand(rng))
                .collect::<Vec<_>>()
        };
        let ro = rand_scalars();
        let rl = rand_scalars();
        let rr = rand_scalars();

        let nl = witness.w_l.clone();
        let nr = witness.w_r.clone();
        let no = (0..self.dim_nm)
            .map(|j| {
                (self.partition)(PartitionType::NO, j)
                    .map(|i| witness.w_o[i])
                    .unwrap_or(C::ScalarField::default())
            })
            .collect::<Vec<_>>();
        let lo = (0..self.dim_nv)
            .map(|j| {
                (self.partition)(PartitionType::LO, j)
                    .map(|i| witness.w_o[i])
                    .unwrap_or(C::ScalarField::default())
            })
            .collect::<Vec<_>>();
        let ll = (0..self.dim_nv)
            .map(|j| {
                (self.partition)(PartitionType::LL, j)
                    .map(|i| witness.w_o[i])
                    .unwrap_or(C::ScalarField::default())
            })
            .collect::<Vec<_>>();
        let lr = (0..self.dim_nv)
            .map(|j| {
                (self.partition)(PartitionType::LR, j)
                    .map(|i| witness.w_o[i])
                    .unwrap_or(C::ScalarField::default())
            })
            .collect::<Vec<_>>();

        let co =
            vector_mul(&self.h_vec, &[&ro[..], &lo[..]].concat()) + vector_mul(&self.g_vec, &no);
        let cl =
            vector_mul(&self.h_vec, &[&rl[..], &ll[..]].concat()) + vector_mul(&self.g_vec, &nl);
        let cr =
            vector_mul(&self.h_vec, &[&rr[..], &lr[..]].concat()) + vector_mul(&self.g_vec, &nr);

        transcript::app_point(b"commitment_cl", &cl, t);
        transcript::app_point(b"commitment_cr", &cr, t);
        transcript::app_point(b"commitment_co", &co, t);

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

        let ls = (0..self.dim_nv)
            .map(|_| C::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let ns = (0..self.dim_nm)
            .map(|_| C::ScalarField::rand(rng))
            .collect::<Vec<_>>();

        let two = C::ScalarField::from(2u32);

        let mut v_0 = C::ScalarField::default();
        for i in 0..self.k {
            v_0 += witness.v[i][0] * self.linear_comb_coef(i, &lambda, &mu);
        }
        v_0 = v_0 * two;

        let mut rv = vec![C::ScalarField::default(); 9];
        for i in 0..self.k {
            rv[0] += witness.s_v[i] * self.linear_comb_coef(i, &lambda, &mu);
        }
        rv[0] = rv[0] * two;

        let mut v_1 = vec![C::ScalarField::default(); self.dim_nv - 1];
        for i in 0..self.k {
            let comb = self.linear_comb_coef(i, &lambda, &mu);
            v_1 = vector_add(&v_1, &vector_mul_on_scalar(&witness.v[i][1..], &comb));
        }
        v_1 = vector_mul_on_scalar(&v_1, &two);

        let c_l0 = self.collect_cl0(&lambda, &mu);

        let delta2 = delta * delta;
        let delta_inv = delta.inverse().unwrap();

        // f_[-2..6] coefficients vector
        let mut f_ = vec![C::ScalarField::default(); 8];

        // -2
        f_[0] = minus(&weight_vector_mul(&ns, &ns, &mu));
        // -1
        f_[1] = vector_mul(&c_l0, &ls) + delta * two * weight_vector_mul(&ns, &no, &mu);
        // 0
        f_[2] = minus(&(vector_mul(&c_lR, &ls) * two))
            - vector_mul(&c_l0, &lo) * delta
            - weight_vector_mul(&ns, &vector_add(&nl, &c_nR), &mu) * two
            - weight_vector_mul(&no, &no, &mu) * delta2;
        // 1
        f_[3] = vector_mul(&c_lL, &ls) * two
            + vector_mul(&c_lR, &lo) * delta * two
            + vector_mul(&c_l0, &ll)
            + weight_vector_mul(&ns, &vector_add(&nr, &c_nL), &mu) * two
            + weight_vector_mul(&no, &vector_add(&nl, &c_nR), &mu) * two * delta;
        // 2
        f_[4] = weight_vector_mul(&c_nR, &c_nR, &mu)
            - vector_mul(&c_lO, &ls) * delta_inv * two
            - vector_mul(&c_lL, &lo) * delta * two
            - vector_mul(&c_lR, &ll) * two
            - vector_mul(&c_l0, &lr)
            - weight_vector_mul(&ns, &c_nO, &mu) * delta_inv * two
            - weight_vector_mul(&no, &vector_add(&nr, &c_nL), &mu) * delta * two
            - weight_vector_mul(&vector_add(&nl, &c_nR), &vector_add(&nl, &c_nR), &mu);
        // 3 (should be zero)
        f_[5] = weight_vector_mul(&c_nO, &c_nR, &mu) * delta_inv * two
            + weight_vector_mul(&c_nL, &c_nL, &mu)
            - vector_mul(&c_lO, &ll) * delta_inv * two
            - vector_mul(&c_lL, &lr) * two
            - vector_mul(&c_lR, &v_1) * two
            - weight_vector_mul(&vector_add(&nl, &c_nR), &c_nO, &mu) * delta_inv * two
            - weight_vector_mul(&vector_add(&nr, &c_nL), &vector_add(&nr, &c_nL), &mu);
        // 4
        f_[6] = minus(&(weight_vector_mul(&c_nO, &c_nL, &mu) * delta_inv * two))
            + vector_mul(&c_nO, &lr) * delta_inv * two
            + vector_mul(&c_lL, &v_1) * two
            + weight_vector_mul(&vector_add(&nr, &c_nL), &c_nO, &mu) * delta_inv * two;
        // 5
        f_[7] = minus(&(vector_mul(&c_lO, &v_1) * delta_inv * two));

        let beta_inv = beta.inverse().unwrap();

        let rs = vec![
            f_[1] + ro[1] * delta * beta,
            f_[0] * beta_inv,
            ro[0] * delta + f_[2] * beta_inv - rl[1],
            (f_[3] - rl[0]) * beta_inv + ro[2] * delta + rr[1],
            (f_[4] + rr[0]) * beta_inv + ro[3] * delta - rl[2],
            minus(&(rv[0] * beta_inv)),
            (f_[5] * beta_inv + ro[5] * delta + rr[3] - rl[4]),
            (f_[6] * beta_inv + rr[4] + ro[6] * delta - rl[5]),
            (f_[7] * beta_inv + ro[7] * delta - rl[6] + rr[5]),
        ];

        let cs =
            vector_mul(&self.h_vec, &[&rs[..], &ls[..]].concat()) + vector_mul(&self.g_vec, &ns);

        transcript::app_point(b"commitment_cs", &cs, t);

        let tau = transcript::get_challenge::<C::ScalarField>(b"circuit_tau", t);
        let tau_inv = tau.inverse().unwrap();
        let tau2 = tau * tau;
        let tau3 = tau2 * tau;

        let mut l = vector_mul_on_scalar(&[&rs[..], &ls[..]].concat(), &tau_inv);
        l = vector_sub(
            &l,
            &vector_mul_on_scalar(&[&ro[..], &lo[..]].concat(), &delta),
        );
        l = vector_add(
            &l,
            &vector_mul_on_scalar(&[&rl[..], &ll[..]].concat(), &tau),
        );
        l = vector_sub(
            &l,
            &vector_mul_on_scalar(&[&rr[..], &lr[..]].concat(), &tau2),
        );
        l = vector_add(
            &l,
            &vector_mul_on_scalar(&[&rv[..], &v_1[..]].concat(), &tau3),
        );

        let mut pn_tau = vector_mul_on_scalar(&c_nO, &(tau3 * delta_inv));
        pn_tau = vector_sub(&pn_tau, &vector_mul_on_scalar(&c_nL, &tau2));
        pn_tau = vector_add(&pn_tau, &vector_mul_on_scalar(&c_nR, &tau));

        let ps_tau = weight_vector_mul(&pn_tau, &pn_tau, &mu)
            + vector_mul(&lambda_vec, &self.a_l) * tau3 * two
            - vector_mul(&mu_vec, &self.a_m) * tau3 * two;

        let mut n_tau = vector_mul_on_scalar(&ns, &tau_inv);
        n_tau = vector_sub(&n_tau, &vector_mul_on_scalar(&no, &delta));
        n_tau = vector_add(&n_tau, &vector_mul_on_scalar(&nl, &tau));
        n_tau = vector_sub(&n_tau, &vector_mul_on_scalar(&nr, &tau2));

        let mut n = vector_add(&pn_tau, &n_tau);

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

        let mut cl_tau = vector_mul_on_scalar(&c_lO, &(tau3 * delta_inv));
        cl_tau = vector_sub(&cl_tau, &vector_mul_on_scalar(&c_lL, &tau2));
        cl_tau = vector_add(&cl_tau, &vector_mul_on_scalar(&c_lR, &tau));
        cl_tau = vector_mul_on_scalar(&cl_tau, &two);
        cl_tau = vector_sub(&cl_tau, &c_l0);

        let mut c = [&cr_tau[..], &cl_tau[..]].concat();

        let v = ps_tau + tau3 * v_0;

        let commitment = self.g * v + vector_mul(&self.h_vec, &l) + vector_mul(&self.g_vec, &n);

        // pad l, c, n to the vector sizes expected by WeightNormLinearArgument
        while l.len() < self.h_vec.len() + self.h_vec_.len() {
            l.push(C::ScalarField::default());
            c.push(C::ScalarField::default());
        }
        while n.len() < self.g_vec.len() + self.g_vec_.len() {
            n.push(C::ScalarField::default());
        }

        let wnla = WeightNormLinearArgument {
            g: self.g,
            g_vec: [&self.g_vec[..], &self.g_vec_[..]].concat(),
            h_vec: [&self.h_vec[..], &self.h_vec_[..]].concat(),
            c,
            rho,
            mu,
        };

        let proof_wnla = wnla.prove(&commitment, t, l, n);

        Proof {
            c_l: cl,
            c_r: cr,
            c_o: co,
            c_s: cs,
            r: proof_wnla.r,
            x: proof_wnla.x,
            l: proof_wnla.l,
            n: proof_wnla.n,
        }
    }

    fn linear_comb_coef(
        &self,
        i: usize,
        lambda: &C::ScalarField,
        mu: &C::ScalarField,
    ) -> C::ScalarField {
        let mut coef = C::ScalarField::default();
        if self.f_l {
            coef += pow(lambda, self.dim_nv * i);
        }
        if self.f_m {
            coef += pow(mu, self.dim_nv * i + 1);
        }
        coef
    }

    fn collect_cl0(&self, lambda: &C::ScalarField, mu: &C::ScalarField) -> Vec<C::ScalarField> {
        let mut c_l0 = vec![C::ScalarField::default(); self.dim_nv - 1];
        if self.f_l {
            let l_pow = e(lambda, self.dim_nv);
            for i in 1..self.dim_nv {
                c_l0[i - 1] = l_pow[i];
            }
        }
        if self.f_m {
            let m_pow = e(mu, self.dim_nv);
            for i in 1..self.dim_nv {
                c_l0[i - 1] -= m_pow[i] * mu.clone();
            }
        }
        c_l0
    }

    fn collect_c(
        &self,
        lambda_vec: &[C::ScalarField],
        mu_vec: &[C::ScalarField],
        mu: &C::ScalarField,
    ) -> (
        Vec<C::ScalarField>,
        Vec<C::ScalarField>,
        Vec<C::ScalarField>,
        Vec<C::ScalarField>,
        Vec<C::ScalarField>,
        Vec<C::ScalarField>,
    ) {
        let (M_lnL, M_mnL, M_lnR, M_mnR) = self.collect_m_rl();
        let (M_lnO, M_mnO, M_llL, M_mlL, M_llR, M_mlR, M_llO, M_mlO) = self.collect_m_o();

        let mu_diag_inv = diag_inv(mu, self.dim_nm);

        let c_nL = vector_mul_on_matrix(
            &vector_sub(
                &vector_mul_on_matrix(lambda_vec, &M_lnL),
                &vector_mul_on_matrix(mu_vec, &M_mnL),
            ),
            &mu_diag_inv,
        );
        let c_nR = vector_mul_on_matrix(
            &vector_sub(
                &vector_mul_on_matrix(lambda_vec, &M_lnR),
                &vector_mul_on_matrix(mu_vec, &M_mnR),
            ),
            &mu_diag_inv,
        );
        let c_nO = vector_mul_on_matrix(
            &vector_sub(
                &vector_mul_on_matrix(lambda_vec, &M_lnO),
                &vector_mul_on_matrix(mu_vec, &M_mnO),
            ),
            &mu_diag_inv,
        );

        let c_lL = vector_sub(
            &vector_mul_on_matrix(lambda_vec, &M_llL),
            &vector_mul_on_matrix(mu_vec, &M_mlL),
        );
        let c_lR = vector_sub(
            &vector_mul_on_matrix(lambda_vec, &M_llR),
            &vector_mul_on_matrix(mu_vec, &M_mlR),
        );
        let c_lO = vector_sub(
            &vector_mul_on_matrix(lambda_vec, &M_llO),
            &vector_mul_on_matrix(mu_vec, &M_mlO),
        );

        (c_nL, c_nR, c_nO, c_lL, c_lR, c_lO)
    }

    fn collect_lambda(&self, lambda: &C::ScalarField, mu: &C::ScalarField) -> Vec<C::ScalarField> {
        let mut lambda_vec = e(lambda, self.dim_nl);
        if self.f_l && self.f_m {
            let t1 = vector_tensor_mul(
                &vector_mul_on_scalar(&e(lambda, self.dim_nv), mu),
                &e(&pow(mu, self.dim_nv), self.k),
            );
            let t2 = vector_tensor_mul(&e(mu, self.dim_nv), &e(&pow(lambda, self.dim_nv), self.k));
            lambda_vec = vector_sub(&lambda_vec, &vector_add(&t1, &t2));
        }
        lambda_vec
    }

    fn collect_m_rl(
        &self,
    ) -> (
        Vec<Vec<C::ScalarField>>,
        Vec<Vec<C::ScalarField>>,
        Vec<Vec<C::ScalarField>>,
        Vec<Vec<C::ScalarField>>,
    ) {
        let M_lnL = (0..self.dim_nl)
            .map(|i| self.W_l[i][..self.dim_nm].to_vec())
            .collect::<Vec<_>>();
        let M_mnL = (0..self.dim_nm)
            .map(|i| self.W_m[i][..self.dim_nm].to_vec())
            .collect::<Vec<_>>();
        let M_lnR = (0..self.dim_nl)
            .map(|i| self.W_l[i][self.dim_nm..self.dim_nm * 2].to_vec())
            .collect::<Vec<_>>();
        let M_mnR = (0..self.dim_nm)
            .map(|i| self.W_m[i][self.dim_nm..self.dim_nm * 2].to_vec())
            .collect::<Vec<_>>();
        (M_lnL, M_mnL, M_lnR, M_mnR)
    }

    fn collect_m_o(
        &self,
    ) -> (
        Vec<Vec<C::ScalarField>>,
        Vec<Vec<C::ScalarField>>,
        Vec<Vec<C::ScalarField>>,
        Vec<Vec<C::ScalarField>>,
        Vec<Vec<C::ScalarField>>,
        Vec<Vec<C::ScalarField>>,
        Vec<Vec<C::ScalarField>>,
        Vec<Vec<C::ScalarField>>,
    ) {
        let W_lO = (0..self.dim_nl)
            .map(|i| self.W_l[i][self.dim_nm * 2..].to_vec())
            .collect::<Vec<_>>();
        let W_mO = (0..self.dim_nm)
            .map(|i| self.W_m[i][self.dim_nm * 2..].to_vec())
            .collect::<Vec<_>>();

        let map_f = |isz: usize,
                     jsz: usize,
                     typ: PartitionType,
                     W_x: &Vec<Vec<C::ScalarField>>|
         -> Vec<Vec<C::ScalarField>> {
            (0..isz)
                .map(|i| {
                    (0..jsz)
                        .map(|j| {
                            if let Some(j_) = (self.partition)(typ, j) {
                                W_x[i][j_]
                            } else {
                                C::ScalarField::default()
                            }
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        };

        let M_lnO = map_f(self.dim_nl, self.dim_nm, PartitionType::NO, &W_lO);
        let M_llL = map_f(self.dim_nl, self.dim_nv, PartitionType::LL, &W_lO);
        let M_llR = map_f(self.dim_nl, self.dim_nv, PartitionType::LR, &W_lO);
        let M_llO = map_f(self.dim_nl, self.dim_nv, PartitionType::LO, &W_lO);

        let M_mnO = map_f(self.dim_nm, self.dim_nm, PartitionType::NO, &W_mO);
        let M_mlL = map_f(self.dim_nm, self.dim_nv, PartitionType::LL, &W_mO);
        let M_mlR = map_f(self.dim_nm, self.dim_nv, PartitionType::LR, &W_mO);
        let M_mlO = map_f(self.dim_nm, self.dim_nv, PartitionType::LO, &W_mO);

        (M_lnO, M_mnO, M_llL, M_mlL, M_llR, M_mlR, M_llO, M_mlO)
    }
}
