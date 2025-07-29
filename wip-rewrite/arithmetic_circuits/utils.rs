/// This module provides utilities for arithmetic circuits in Bulletproofs++.
///
/// It includes the `WitnessLocation` enum to represent the location of witnesses in the circuit,
/// and a `LayoutMap` type to map output witnesses to their corresponding linear components.
use hashbrown::HashMap;

/// Represents the location of a witness in the circuit
/// This is used to map output witnesses to their corresponding linear components.
////// The enum variants indicate the type of witness location:
/// - `LO`: Output witness
/// - `LL`: Left linear component
/// - `LR`: Right linear component
/// - `NO`: Norm component
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessLocation {
    LO,
    LL,
    LR,
    NO,
}

// Witness layout mapping function type
// maps wo index to its location in lo/lr/ll/no
pub type LayoutMapFn = HashMap<usize, WitnessLocation>;

type Matrix<T> = Vec<Vec<T>>;

/// Common inputs for arithmetic circuit protocols
#[derive(Debug, Clone)]
pub struct ArithmeticCircuit<G, F> {
    // Generators for commitments
    pub g: G,          // G ∈ G
    pub g_vec: Vec<G>, // G ∈ G^Nm
    pub h_vec: Vec<G>, // H ∈ G^(Nv+7)

    // In BP++, an arithmetic circuit C will be represented using:
    // 2 matrices (Wl,Wm), 2 vectors (al,am) and 2 binary flags (fl,fm).
    //
    pub wm: Matrix<F>,         // Wm ∈ F^(Nm×Nw)
    pub wl: Matrix<F>,         // Wl ∈ F^(Nl×Nw)
    pub am: Vec<F>,            // am ∈ F^Nm
    pub al: Vec<F>,            // al ∈ F^Nl
    pub fl: bool,              // fl ∈ {0,1}
    pub fm: bool,              // fm ∈ {0,1}
    pub v_commitments: Vec<G>, // V ∈ G^k
    pub nm: usize,             // Nm ∈ N
    pub nl: usize,             // Nm ∈ N
    pub na: usize,             // Nl ∈ N
}
