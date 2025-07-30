use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::{BigInteger, PrimeField};
use ark_secp256k1::Fq;
use ark_secp256k1::{Affine, Config as ArkConf, Fr, Projective};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::PrimeField as KPrimeField;
use k256::FieldElement;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use std::ops::Mul;

impl UnifiedPrint for Fr {
    fn pr(&self) -> String {
        format!("{}", hex(&self.into_bigint().to_bytes_be()))
    }
}

impl UnifiedPrint for Scalar {
    fn pr(&self) -> String {
        format!("{}", hex(&self.to_bytes()))
    }
}

impl UnifiedPrint for Projective {
    fn pr(&self) -> String {
        self.into_affine().pr()
    }
}
impl UnifiedPrint for Affine {
    fn pr(&self) -> String {
        let (x, _) = self.xy().unwrap();

        format!("{}", hex(&x.into_bigint().to_bytes_be()))
    }
}

impl UnifiedPrint for ProjectivePoint {
    fn pr(&self) -> String {
        (&self.to_affine()).pr()
    }
}
impl UnifiedPrint for AffinePoint {
    fn pr(&self) -> String {
        format!("{}", hex(&self.x()))
    }
}

impl<T: UnifiedPrint + Copy> UnifiedPrint for &[T] {
    fn pr(&self) -> String {
        let mut ret = String::new();

        self.iter().for_each(|f| {
            ret.push_str("\n");
            ret.push_str(&f.pr());
        });
        ret
    }
}

/// Print k256 and ark_ff projective points in a unified way
pub trait UnifiedPrint {
    fn pr(&self) -> String;
}

/// Base field k256 to ark_ff
pub fn bf_k2a(s: &FieldElement) -> Fq {
    let bytes = s.to_bytes();
    Fq::from_be_bytes_mod_order(&bytes)
}

/// Base field ark_ff to k256
pub fn bf_a2k(s: &Fq) -> FieldElement {
    let str = s.into_bigint().to_string();
    FieldElement::from_str_vartime(&str).unwrap()
}

/// Scalar field k256 to ark_ff
pub fn f_k2a(s: &Scalar) -> Fr {
    let bytes = s.to_bytes();
    Fr::from_be_bytes_mod_order(&bytes)
}

/// Scalar field ark_ff to k256
pub fn f_a2k(s: &Fr) -> Scalar {
    let str = s.into_bigint().to_string();
    Scalar::from_str_vartime(&str).unwrap()
}

/// Projective Point k256 to ark_ff
pub fn pt_k2a(p: &ProjectivePoint) -> Projective {
    let p = p.to_affine();
    let xf = Fq::from_be_bytes_mod_order(&p.x.to_bytes());
    let yf = Fq::from_be_bytes_mod_order(&p.y.to_bytes());
    Projective::new(xf, yf, Fq::ONE)
}

/// Projective Point ark_ff to k256
pub fn pt_a2k(p: &Projective) -> ProjectivePoint {
    let p = p.into_affine();
    let xs = p.x.into_bigint().to_string();
    let ys = p.y.into_bigint().to_string();

    AffinePoint::new(
        FieldElement::from_str_vartime(&xs).unwrap(),
        FieldElement::from_str_vartime(&ys).unwrap(),
    )
    .into()
}

/// Convert bytes to lowercase hex string
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// k256 projective point generator
pub fn pt_k(n: u32) -> ProjectivePoint {
    let n = Scalar::from(n);
    k256::ProjectivePoint::GENERATOR.mul(n)
}

/// ark_ff projective point generator
pub fn pt_a(n: u32) -> Projective {
    ArkConf::GENERATOR * Fr::from(n)
}
