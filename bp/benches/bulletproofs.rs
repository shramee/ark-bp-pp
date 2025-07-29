use criterion::{criterion_group, criterion_main, Criterion};
use ark_bp::{inner_product, powers, hadamard_product};
use ark_starkcurve::Fr;
use ark_ff::Field;
use ark_std::rand::RngCore;

fn bench_inner_product(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();
    
    for size in [32, 64, 128, 256, 512, 1024].iter() {
        let a: Vec<Fr> = (0..*size).map(|_| Fr::rand(&mut rng)).collect();
        let b: Vec<Fr> = (0..*size).map(|_| Fr::rand(&mut rng)).collect();
        
        c.bench_function(&format!("inner_product_{}", size), |bench| {
            bench.iter(|| inner_product(&a, &b))
        });
    }
}

fn bench_powers(c: &mut Criterion) {
    let x = Fr::from(42u64);
    
    for size in [32, 64, 128, 256, 512, 1024].iter() {
        c.bench_function(&format!("powers_{}", size), |bench| {
            bench.iter(|| powers(x, *size))
        });
    }
}

fn bench_hadamard_product(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();
    
    for size in [32, 64, 128, 256, 512, 1024].iter() {
        let a: Vec<Fr> = (0..*size).map(|_| Fr::rand(&mut rng)).collect();
        let b: Vec<Fr> = (0..*size).map(|_| Fr::rand(&mut rng)).collect();
        
        c.bench_function(&format!("hadamard_product_{}", size), |bench| {
            bench.iter(|| hadamard_product(&a, &b))
        });
    }
}

criterion_group!(benches, bench_inner_product, bench_powers, bench_hadamard_product);
criterion_main!(benches);
