#![allow(non_snake_case)]

pub mod conv_print_utils;
pub mod types_conv;
pub use conv_print_utils::*;

#[cfg(test)]
mod circuit_tests {
    use ark_bp_pp::arithmetic_circuits::*;
    use ark_secp256k1::{Fr, Projective};

    use ark_std::{test_rng, vec::Vec};
    use bp_pp::circuit::{
        ArithmeticCircuit as DLCircuit, PartitionType as DLPartitionType, Witness as DLWitness,
    };
    use bp_pp::util::minus;
    use k256::elliptic_curve::rand_core::OsRng;
    use k256::{ProjectivePoint, Scalar};
    use std::ops::Sub;

    use crate::{pt_a, pt_k, UnifiedPrint};

    #[test]
    fn k256() {
        let mut rand = OsRng::default();
        // Test the knowledge of x, y for public z, r, such:
        // x + y = r
        // x * y = z

        let x = Scalar::from(3u32);
        let y = Scalar::from(5u32);

        let r = Scalar::from(8u32);
        let z = Scalar::from(15u32);

        let w_l = vec![Scalar::from(x)];
        let w_r = vec![Scalar::from(y)];
        let w_o = vec![Scalar::from(z), Scalar::from(r)];

        let dim_nm = 1;
        let dim_no = 2;
        let dim_nv = 2;
        let k = 1;

        let dim_nl = dim_nv * k; // 2
        let dim_nw = dim_nm + dim_nm + dim_no; // 4

        let W_m = vec![vec![Scalar::ZERO, Scalar::ZERO, Scalar::ONE, Scalar::ZERO]]; // Nm*Nw
        let a_m = vec![Scalar::ZERO]; // Nm

        let W_l = vec![
            vec![Scalar::ZERO, Scalar::ONE, Scalar::ZERO, Scalar::ZERO],
            vec![
                Scalar::ZERO,
                Scalar::ZERO.sub(&Scalar::ONE),
                Scalar::ONE,
                Scalar::ZERO,
            ],
        ]; // Nl*Nw

        let a_l = vec![minus(&r), minus(&z)]; // Nl

        //let w_v = vec![Scalar::from(x), Scalar::from(y)];
        //let w = vec![Scalar::from(x), Scalar::from(y), Scalar::from(z), Scalar::from(r)]; // w = wl||wr||wo
        //println!("Circuit check: {:?} = {:?}", vector_mul(&W_m[0], &w), vector_hadamard_mul(&w_l, &w_r));
        //println!("Circuit check: {:?} = 0", vector_add(&vector_add(&vec![vector_mul(&W_l[0], &w), vector_mul(&W_l[1], &w)], &w_v), &a_l));

        let g = pt_k(95484835);
        let g_vec = (0..1)
            .map(|i| pt_k(23415 * i))
            .collect::<Vec<ProjectivePoint>>();
        let h_vec = (0..16)
            .map(|i| pt_k(i + i * 3))
            .collect::<Vec<ProjectivePoint>>();

        let partition = |typ: DLPartitionType, index: usize| -> Option<usize> {
            match typ {
                DLPartitionType::LL => Some(index),
                _ => None,
            }
        };

        let circuit = DLCircuit {
            dim_nm,
            dim_no,
            k,
            dim_nl,
            dim_nv,
            dim_nw,
            g,
            g_vec: g_vec[..dim_nm].to_vec(),
            h_vec: h_vec[..9 + dim_nv].to_vec(),
            W_m,
            W_l,
            a_m,
            a_l,
            f_l: true,
            f_m: false,
            g_vec_: g_vec[dim_nm..].to_vec(),
            h_vec_: h_vec[9 + dim_nv..].to_vec(),
            partition,
        };

        let witness = DLWitness {
            v: vec![vec![x, y]],
            s_v: vec![Scalar::from(234352_u32)],
            w_l,
            w_r,
            w_o,
        };

        let v = (0..k)
            .map(|i| circuit.commit(&witness.v[i], &witness.s_v[i]))
            .collect::<Vec<ProjectivePoint>>();

        let mut pt = merlin::Transcript::new(b"circuit test");
        let proof = circuit.prove::<OsRng>(&v, witness, &mut pt, &mut rand);

        // ser_proof.c_l.upr("KCL:");
        println!("{}", pt_k(25).pr());

        let mut vt = merlin::Transcript::new(b"circuit test");
        assert!(circuit.verify(&v, &mut vt, proof));
    }

    #[test]
    fn ark() {
        let mut rand = test_rng();

        // Test the knowledge of x, y for public z, r, such:
        // x + y = r
        // x * y = z
        let zero = Fr::default();
        let one = Fr::from(1_u32);

        let x = Fr::from(3u32);
        let y = Fr::from(5u32);

        let r = Fr::from(8u32);
        let z = Fr::from(15u32);

        let w_l = vec![Fr::from(x)];
        let w_r = vec![Fr::from(y)];
        let w_o = vec![Fr::from(z), Fr::from(r)];

        let dim_nm = 1;
        let dim_no = 2;
        let dim_nv = 2;
        let k = 1;

        let dim_nl = dim_nv * k; // 2
        let dim_nw = dim_nm + dim_nm + dim_no; // 4

        let W_m = vec![vec![zero, zero, one, zero]]; // Nm*Nw
        let a_m = vec![zero]; // Nm

        let W_l = vec![vec![zero, one, zero, zero], vec![zero, -one, one, zero]]; // Nl*Nw

        let a_l = vec![-r, -z]; // Nl

        let g = pt_a(95484835);
        let g_vec = (0..1).map(|i| pt_a(23415 * i)).collect::<Vec<Projective>>();
        let h_vec = (0..16)
            .map(|i| pt_a(i + i * 3))
            .collect::<Vec<Projective>>();

        let partition = |typ: PartitionType, index: usize| -> Option<usize> {
            match typ {
                PartitionType::LL => Some(index),
                _ => None,
            }
        };

        let circuit = ArithmeticCircuit {
            dim_nm,
            dim_no,
            k,
            dim_nl,
            dim_nv,
            dim_nw,
            g,
            g_vec: g_vec[..dim_nm].to_vec(),
            h_vec: h_vec[..9 + dim_nv].to_vec(),
            W_m,
            W_l,
            a_m,
            a_l,
            f_l: true,
            f_m: false,
            g_vec_: g_vec[dim_nm..].to_vec(),
            h_vec_: h_vec[9 + dim_nv..].to_vec(),
            partition,
            // _phantom: std::marker::PhantomData,
        };

        let witness = Witness {
            v: vec![vec![x, y]],
            s_v: vec![Fr::from(234352_u32)],
            w_l,
            w_r,
            w_o,
        };

        let v = (0..k)
            .map(|i| circuit.commit(&witness.v[i], &witness.s_v[i]))
            .collect::<Vec<Projective>>();

        let mut pt = merlin::Transcript::new(b"circuit test");
        let proof = circuit.prove(&v, witness, &mut pt, &mut rand);
        // let ser_proof = SerializableProof::from(&proof);

        // print_pt("ACL:", ser_proof.c_l);
        println!("{}", pt_a(25).pr());

        let mut vt = merlin::Transcript::new(b"circuit test");
        assert!(circuit.verify(&v, &mut vt, proof));
    }
}
