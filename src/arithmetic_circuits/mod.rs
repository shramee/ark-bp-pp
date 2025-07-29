#![allow(non_snake_case)]

//! Definition and implementation of the Bulletproofs++ arithmetic circuit protocol.

pub mod prover;
pub mod types;
pub mod utils;
pub mod verifier;

pub use prover::*;
pub use utils::*;
pub use verifier::*;

#[cfg(test)]
mod circuit_tests {
    use super::*;

    use ark_ff::UniformRand;
    use ark_starkcurve::{Fr, Projective};
    use ark_std::{test_rng, vec::Vec};

    #[test]
    fn ac_works() {
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

        //let w_v = vec![Fr::from(x), Fr::from(y)];
        //let w = vec![Fr::from(x), Fr::from(y), Fr::from(z), Fr::from(r)]; // w = wl||wr||wo
        //println!("Circuit check: {:?} = {:?}", vector_mul(&W_m[0], &w), vector_hadamard_mul(&w_l, &w_r));
        //println!("Circuit check: {:?} = 0", vector_add(&vector_add(&vec![vector_mul(&W_l[0], &w), vector_mul(&W_l[1], &w)], &w_v), &a_l));

        let g = Projective::rand(&mut rand);
        let g_vec = (0..1)
            .map(|_| Projective::rand(&mut rand))
            .collect::<Vec<Projective>>();
        let h_vec = (0..16)
            .map(|_| Projective::rand(&mut rand))
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
            s_v: vec![Fr::rand(&mut rand)],
            w_l,
            w_r,
            w_o,
        };

        let v = (0..k)
            .map(|i| circuit.commit(&witness.v[i], &witness.s_v[i]))
            .collect::<Vec<Projective>>();

        let mut pt = merlin::Transcript::new(b"circuit test");
        let proof = circuit.prove(&v, witness, &mut pt, &mut rand);

        println!("{:?}", SerializableProof::from(&proof));

        let mut vt = merlin::Transcript::new(b"circuit test");
        assert!(circuit.verify(&v, &mut vt, proof));
    }
}
