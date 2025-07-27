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
    LO(usize),
    LL(usize),
    LR(usize),
    NO(usize),
}

pub type LayoutMapFn = HashMap<usize, WitnessLocation>;
