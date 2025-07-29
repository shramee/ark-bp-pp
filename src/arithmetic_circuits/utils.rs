pub use super::types::*;
use ark_ec::CurveGroup;
use ark_std::vec::Vec;

use crate::util::*;

impl<'a, C, P> ArithmeticCircuit<'a, C, P>
where
    C: CurveGroup,
    P: Fn(PartitionType, usize) -> Option<usize> + 'a,
{
    /// Creates commitment to the arithmetic circuit witness.
    pub fn commit(&self, v: &[C::ScalarField], s: &C::ScalarField) -> C {
        self.g * v[0] + self.h_vec[0] * s + vector_mul(&self.h_vec[9..], &v[1..])
    }

    pub fn linear_comb_coef(
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

    pub fn collect_cl0(&self, lambda: &C::ScalarField, mu: &C::ScalarField) -> Vec<C::ScalarField> {
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

    pub fn collect_c(
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

    pub fn collect_lambda(
        &self,
        lambda: &C::ScalarField,
        mu: &C::ScalarField,
    ) -> Vec<C::ScalarField> {
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

    pub fn collect_m_rl(
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

    pub fn collect_m_o(
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
