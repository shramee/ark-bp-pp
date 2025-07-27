//! Generic utility functions for vector operations in Bulletproofs++
//!
//! This module provides curve-agnostic utility functions for vector manipulations
//! used in the Weight Norm Linear Argument and arithmetic circuit protocols.

use ark_ff::Field;
use ark_std::{
    ops::{Add, Mul, Sub},
    rand::SeedableRng,
    vec::Vec,
};
use std::cmp::max;

/// Generates a random vector of field elements.
/// This is used for creating random blinding factors vectors.
pub fn sample_random_vector<F: Field>(n: usize) -> Vec<F> {
    let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
    (0..n).map(|_| F::rand(&mut rng)).collect::<Vec<F>>()
}

/// Reduces a vector by splitting it into even and odd indexed components.
///
/// This is a key operation in the vector reduction strategy used by Bulletproofs++.
/// Unlike traditional left/right splitting, this uses even/odd indices which can
/// improve locality in some implementations.
///
/// # Arguments
/// * `v` - Input vector to reduce
///
/// # Returns
/// Tuple `(even_elements, odd_elements)` where:
/// - `even_elements` = `[v[0], v[2], v[4], ...]`
/// - `odd_elements` = `[v[1], v[3], v[5], ...]`
///
/// # Example
/// ```
/// use ark_bp_pp::util::reduce;
/// let v = vec![1, 2, 3, 4, 5];
/// let (even, odd) = reduce(&v);
/// assert_eq!(even, vec![1, 3, 5]);
/// assert_eq!(odd, vec![2, 4]);
/// ```
pub fn reduce<T: Copy>(v: &[T]) -> (Vec<T>, Vec<T>) {
    let res0 = v
        .iter()
        .enumerate()
        .filter(|(i, _)| *i as i32 % 2 == 0)
        .map(|(_, x)| *x)
        .collect::<Vec<T>>();

    let res1 = v
        .iter()
        .enumerate()
        .filter(|(i, _)| *i as i32 % 2 == 1)
        .map(|(_, x)| *x)
        .collect::<Vec<T>>();

    (res0, res1)
}

/// Extends a vector to a specified length, padding with default values.
///
/// This ensures vectors have compatible lengths for operations, padding
/// shorter vectors with the default value of type T.
///
/// # Arguments
/// * `v` - Input vector to extend
/// * `n` - Target length
///
/// # Returns
/// Vector of length `n` where `result[i] = v[i]` if `i < v.len()`,
/// otherwise `result[i] = T::default()`
pub fn vector_extend<T: Copy + Default>(v: &[T], n: usize) -> Vec<T> {
    (0..n)
        .map(|i| if i < v.len() { v[i] } else { T::default() })
        .collect::<Vec<T>>()
}

/// Computes the weighted inner product of two vectors.
///
/// This is the core operation for weight norm calculations in WNLA.
/// Computes: `Σᵢ aᵢ · bᵢ · weight^(i+1)`
///
/// # Arguments
/// * `a` - First vector (group elements or scalars)
/// * `b` - Second vector (scalars)
/// * `weight` - Weight parameter μ
///
/// # Returns
/// Weighted inner product result
///
/// # Type Requirements
/// * `T` must support multiplication by scalars and addition
pub fn weight_vector_mul<T, F>(a: &[T], b: &[F], weight: &F) -> T
where
    T: Copy + Default + for<'a> Mul<&'a F, Output = T> + Add<Output = T>,
    F: Field,
{
    let mut exp = F::one();
    let mut result = T::default();
    let a_ext = vector_extend(a, max(a.len(), b.len()));
    let b_ext = vector_extend(b, max(a.len(), b.len()));

    a_ext.iter().zip(b_ext.iter()).for_each(|(a_val, b_val)| {
        exp = exp.mul(weight);
        result = result.add(a_val.mul(&b_val.mul(exp)));
    });

    result
}

/// Computes the standard inner product of two vectors.
///
/// Computes: `Σᵢ aᵢ · bᵢ`
///
/// # Arguments
/// * `a` - First vector (group elements or scalars)
/// * `b` - Second vector (scalars)
///
/// # Returns
/// Inner product result
pub fn vector_mul<T, F>(a: &[T], b: &[F]) -> T
where
    T: Copy + Default + for<'a> Mul<&'a F, Output = T> + Add<Output = T>,
    F: Field,
{
    let mut result = T::default();
    let a_ext = vector_extend(a, max(a.len(), b.len()));
    let b_ext = vector_extend(b, max(a.len(), b.len()));

    a_ext.iter().zip(b_ext.iter()).for_each(|(a_val, b_val)| {
        result = result.add(a_val.mul(b_val));
    });

    result
}

/// Multiplies each element of a vector by a scalar.
///
/// Computes: `[a₀·s, a₁·s, ..., aₙ·s]`
///
/// # Arguments  
/// * `a` - Input vector
/// * `s` - Scalar multiplier
///
/// # Returns
/// Vector where each element is multiplied by the scalar
pub fn vector_mul_on_scalar<T, F>(a: &[T], s: &F) -> Vec<T>
where
    T: Copy + for<'a> Mul<&'a F, Output = T>,
    F: Field,
{
    a.iter().map(|x| x.mul(s)).collect::<Vec<T>>()
}

/// Computes element-wise addition of two vectors.
///
/// If vectors have different lengths, the shorter one is padded with default values.
///
/// # Arguments
/// * `a` - First vector
/// * `b` - Second vector
///
/// # Returns
/// Vector `c` where `c[i] = a[i] + b[i]`
pub fn vector_add<T>(a: &[T], b: &[T]) -> Vec<T>
where
    T: Copy + Default + Add<Output = T>,
{
    let a_ext = vector_extend(a, max(a.len(), b.len()));
    let b_ext = vector_extend(b, max(a.len(), b.len()));

    a_ext
        .iter()
        .zip(b_ext.iter())
        .map(|(a_val, b_val)| a_val.add(*b_val))
        .collect::<Vec<T>>()
}

/// Computes element-wise subtraction of two vectors.
///
/// If vectors have different lengths, the shorter one is padded with default values.
///
/// # Arguments  
/// * `a` - First vector (minuend)
/// * `b` - Second vector (subtrahend)
///
/// # Returns
/// Vector `c` where `c[i] = a[i] - b[i]`
pub fn vector_sub<T>(a: &[T], b: &[T]) -> Vec<T>
where
    T: Copy + Default + Sub<Output = T>,
{
    let a_ext = vector_extend(a, max(a.len(), b.len()));
    let b_ext = vector_extend(b, max(a.len(), b.len()));

    a_ext
        .iter()
        .zip(b_ext.iter())
        .map(|(a_val, b_val)| a_val.sub(*b_val))
        .collect::<Vec<T>>()
}

/// Generates a vector of powers: `[1, v, v², v³, ..., v^(n-1)]`.
///
/// This is used for creating challenge vectors in the protocol.
///
/// # Arguments
/// * `v` - Base value
/// * `n` - Number of powers to generate
///
/// # Returns
/// Vector of powers of `v`
pub fn e<F: Field>(v: &F, n: usize) -> Vec<F> {
    let mut buf = F::one();
    (0..n)
        .map(|_| {
            let val = buf;
            buf = buf.mul(v);
            val
        })
        .collect::<Vec<F>>()
}

/// Computes s^n efficiently using field exponentiation.
///
/// # Arguments
/// * `s` - Base scalar
/// * `n` - Exponent
///
/// # Returns
/// `s^n` in the field
pub fn pow<F: Field>(s: &F, n: usize) -> F {
    // Convert to proper representation for ark-ff pow function
    let mut result = F::one();
    let mut base = *s;
    let mut exp = n;

    while exp > 0 {
        if exp % 2 == 1 {
            result = result * base;
        }
        base = base * base;
        exp /= 2;
    }

    result
}

/// Computes element-wise (Hadamard) product of two vectors.
///
/// Computes: `[a₀·b₀, a₁·b₁, ..., aₙ·bₙ]`
///
/// # Arguments
/// * `a` - First vector  
/// * `b` - Second vector
///
/// # Returns
/// Vector of element-wise products
#[allow(dead_code)]
pub fn vector_hadamard_mul<T, F>(a: &[T], b: &[F]) -> Vec<T>
where
    T: Copy + Default + for<'a> Mul<&'a F, Output = T>,
    F: Field,
{
    let a_ext = vector_extend(a, max(a.len(), b.len()));
    let b_ext = vector_extend(b, max(a.len(), b.len()));

    a_ext
        .iter()
        .zip(b_ext.iter())
        .map(|(a_val, b_val)| a_val.mul(b_val))
        .collect::<Vec<T>>()
}

/// Computes the tensor product of two vectors.
///
/// For vectors `a = [a₀, a₁, ...]` and `b = [b₀, b₁, ...]`,
/// returns `[a₀·b₀, a₀·b₁, ..., a₁·b₀, a₁·b₁, ...]`
///
/// # Arguments
/// * `a` - First vector
/// * `b` - Second vector
///
/// # Returns
/// Flattened tensor product
pub fn vector_tensor_mul<T, F>(a: &[T], b: &[F]) -> Vec<T>
where
    T: Copy + for<'a> Mul<&'a F, Output = T>,
    F: Field,
{
    b.iter()
        .map(|x| vector_mul_on_scalar(a, x))
        .collect::<Vec<Vec<T>>>()
        .concat()
}

/// Creates a diagonal inverse matrix diag(x^(-1), x^(-2), ..., x^(-n)).
///
/// Used in certain arithmetic circuit constructions.
///
/// # Arguments
/// * `x` - Base field element
/// * `n` - Matrix dimension
///
/// # Returns
/// n×n matrix with x^(-i) on the diagonal
pub fn diag_inv<F: Field>(x: &F, n: usize) -> Vec<Vec<F>> {
    let x_inv = x.inverse().unwrap();
    let mut val = F::one();

    (0..n)
        .map(|i| {
            (0..n)
                .map(|j| {
                    if i == j {
                        val = val.mul(x_inv);
                        val
                    } else {
                        F::zero()
                    }
                })
                .collect::<Vec<F>>()
        })
        .collect::<Vec<Vec<F>>>()
}

/// Multiplies a vector by a matrix from the right: `a * M`.
///
/// Computes the result where each element is the inner product
/// of `a` with the corresponding column of `M`.
///
/// # Arguments
/// * `a` - Input vector (1×m)
/// * `m` - Matrix (m×n)
///
/// # Returns
/// Result vector (1×n)
pub fn vector_mul_on_matrix<T, F>(a: &[T], m: &[Vec<F>]) -> Vec<T>
where
    T: Copy + Default + for<'a> Mul<&'a F, Output = T> + Add<Output = T>,
    F: Field,
{
    (0..m[0].len())
        .map(|j| {
            let column = m.iter().map(|row| row[j]).collect::<Vec<F>>();
            vector_mul(a, &column)
        })
        .collect::<Vec<T>>()
}

/// Multiplies a matrix by a vector from the left: `M * a`.
///
/// Computes the result where each element is the inner product
/// of the corresponding row of `M` with `a`.
///
/// # Arguments
/// * `a` - Input vector (n×1)
/// * `m` - Matrix (m×n)
///
/// # Returns  
/// Result vector (m×1)
#[allow(dead_code)]
pub fn matrix_mul_on_vector<T, F>(a: &[T], m: &[Vec<F>]) -> Vec<T>
where
    T: Copy + Default + for<'a> Mul<&'a F, Output = T> + Add<Output = T>,
    F: Field,
{
    m.iter().map(|v| vector_mul(a, v)).collect::<Vec<T>>()
}

/// Computes the additive inverse (negation) in the field.
///
/// For field element `v`, returns `-v` such that `v + (-v) = 0`.
///
/// # Arguments
/// * `v` - Field element to negate
///
/// # Returns
/// Additive inverse `-v`
pub fn minus<F: Field>(v: &F) -> F {
    F::zero().sub(v)
}
