use crate::conv_print_utils::*;
use ark_bp_pp::arithmetic_circuits as abp;
use ark_secp256k1::{Fr, Projective};
use bp_pp::circuit as bp;

/// Convert bp_pp::Proof to ark_bp_pp::Proof
pub fn convert_proof_k2a(proof: &bp::Proof) -> abp::Proof<Projective> {
    abp::Proof {
        c_l: pt_k2a(&proof.c_l),
        c_r: pt_k2a(&proof.c_r),
        c_o: pt_k2a(&proof.c_o),
        c_s: pt_k2a(&proof.c_s),
        r: proof.r.iter().map(|p| pt_k2a(p)).collect(),
        x: proof.x.iter().map(|p| pt_k2a(p)).collect(),
        l: proof.l.iter().map(|s| f_k2a(s)).collect(),
        n: proof.n.iter().map(|s| f_k2a(s)).collect(),
    }
}

/// Convert bp_pp::Witness to ark_bp_pp::Witness
pub fn convert_witness_k2a(witness: &bp::Witness) -> abp::Witness<Fr> {
    abp::Witness {
        v: witness
            .v
            .iter()
            .map(|inner_vec| inner_vec.iter().map(|s| f_k2a(s)).collect())
            .collect(),
        s_v: witness.s_v.iter().map(|s| f_k2a(s)).collect(),
        w_l: witness.w_l.iter().map(|s| f_k2a(s)).collect(),
        w_r: witness.w_r.iter().map(|s| f_k2a(s)).collect(),
        w_o: witness.w_o.iter().map(|s| f_k2a(s)).collect(),
    }
}

/// Convert bp_pp::ArithmeticCircuit to ark_bp_pp::ArithmeticCircuit
pub fn convert_circuit_k2a(
    circuit: &bp::ArithmeticCircuit<impl Fn(bp::PartitionType, usize) -> Option<usize>>,
) -> abp::ArithmeticCircuit<Projective, impl Fn(abp::PartitionType, usize) -> Option<usize>> {
    // Convert partition function
    let partition_fn = |typ: abp::PartitionType, index: usize| -> Option<usize> {
        // Map ark partition type to bp partition type
        let bp_typ = match typ {
            abp::PartitionType::LL => bp::PartitionType::LL,
            abp::PartitionType::LR => bp::PartitionType::LR,
            abp::PartitionType::LO => bp::PartitionType::LO,
            abp::PartitionType::NO => bp::PartitionType::NO,
        };
        (circuit.partition)(bp_typ, index)
    };

    abp::ArithmeticCircuit {
        dim_nm: circuit.dim_nm,
        dim_no: circuit.dim_no,
        k: circuit.k,
        dim_nl: circuit.dim_nl,
        dim_nv: circuit.dim_nv,
        dim_nw: circuit.dim_nw,
        g: pt_k2a(&circuit.g),
        g_vec: circuit.g_vec.iter().map(|p| pt_k2a(p)).collect(),
        h_vec: circuit.h_vec.iter().map(|p| pt_k2a(p)).collect(),
        W_m: circuit
            .W_m
            .iter()
            .map(|row| row.iter().map(|s| f_k2a(s)).collect())
            .collect(),
        W_l: circuit
            .W_l
            .iter()
            .map(|row| row.iter().map(|s| f_k2a(s)).collect())
            .collect(),
        a_m: circuit.a_m.iter().map(|s| f_k2a(s)).collect(),
        a_l: circuit.a_l.iter().map(|s| f_k2a(s)).collect(),
        f_l: circuit.f_l,
        f_m: circuit.f_m,
        g_vec_: circuit.g_vec_.iter().map(|p| pt_k2a(p)).collect(),
        h_vec_: circuit.h_vec_.iter().map(|p| pt_k2a(p)).collect(),
        partition: partition_fn,
    }
}

#[cfg(test)]
mod cross_verification_tests {
    use super::*;
    use crate::{pt_k, UnifiedPrint};
    use ark_secp256k1::{Fr, Projective};
    use bp::{
        ArithmeticCircuit as DLCircuit, PartitionType as DLPartitionType, Witness as DLWitness,
    };
    use bp_pp::util::minus;
    use k256::elliptic_curve::rand_core::OsRng;
    use k256::{ProjectivePoint, Scalar};
    use std::ops::Sub;

    #[test]
    fn test_cross_library_verification() {
        let mut k256_rand = OsRng::default();

        // Test the knowledge of x, y for public z, r, such:
        // x + y = r
        // x * y = z
        let x = Scalar::from(3u32);
        let y = Scalar::from(5u32);
        let r = Scalar::from(8u32);
        let z = Scalar::from(15u32);

        // Create bp_pp circuit and witness
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

        // Create bp_pp circuit
        let bp_circuit = DLCircuit {
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

        let bp_witness = DLWitness {
            v: vec![vec![x, y]],
            s_v: vec![Scalar::from(234352_u32)],
            w_l,
            w_r,
            w_o,
        };

        // Generate commitment and proof using bp_pp
        let v = (0..k)
            .map(|i| bp_circuit.commit(&bp_witness.v[i], &bp_witness.s_v[i]))
            .collect::<Vec<ProjectivePoint>>();

        let mut bp_transcript = merlin::Transcript::new(b"cross verification test");
        let bp_proof = bp_circuit.prove(&v, bp_witness.clone(), &mut bp_transcript, &mut k256_rand);

        // Convert bp_pp types to ark_bp_pp types
        let ark_circuit = convert_circuit_k2a(&bp_circuit);
        let ark_witness = convert_witness_k2a(&bp_witness);
        let ark_proof = convert_proof_k2a(&bp_proof);
        let ark_v = v.iter().map(|p| pt_k2a(p)).collect::<Vec<Projective>>();

        // Verify the converted proof using ark_bp_pp
        let mut ark_transcript = merlin::Transcript::new(b"cross verification test");
        let verification_result = ark_circuit.verify(&ark_v, &mut ark_transcript, ark_proof);

        assert!(
            verification_result,
            "Cross-library verification should succeed"
        );

        println!("✓ Successfully verified bp_pp proof using ark_bp_pp verifier!");
        println!("✓ Cross-library compatibility confirmed");
    }

    #[test]
    fn test_conversion_consistency() {
        // Test that conversions are consistent by converting back and forth
        let original_scalar = Scalar::from(42u32);
        let original_point = pt_k(42);

        // Convert to ark and back
        let ark_scalar = f_k2a(&original_scalar);
        let converted_back_scalar = f_a2k(&ark_scalar);

        let ark_point = pt_k2a(&original_point);
        let converted_back_point = pt_a2k(&ark_point);

        // Check that we get the same values (within the constraints of the conversion)
        println!("Original scalar: {}", original_scalar.pr());
        println!("Converted back scalar: {}", converted_back_scalar.pr());
        println!("Original point: {}", original_point.pr());
        println!("Converted back point: {}", converted_back_point.pr());

        // Note: Due to potential precision/representation differences,
        // we verify the conversion preserves the mathematical properties
        assert_eq!(original_scalar.pr(), converted_back_scalar.pr());
        assert_eq!(original_point.pr(), converted_back_point.pr());

        println!("✓ Conversion consistency verified");
    }
}
