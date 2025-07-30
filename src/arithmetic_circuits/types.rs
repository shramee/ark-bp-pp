use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;

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
#[derive(CanonicalDeserialize, CanonicalSerialize, Clone, Debug)]
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
pub struct ArithmeticCircuit<C, P>
where
    C: CurveGroup,
    P: Fn(PartitionType, usize) -> Option<usize>,
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
}
