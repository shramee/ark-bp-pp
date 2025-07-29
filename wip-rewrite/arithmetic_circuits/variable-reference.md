# Bulletproofs++ Variable Reference

## Circuit Definition Parameters

| Variable | Type             | Description                                                |
| -------- | ---------------- | ---------------------------------------------------------- |
| `Wl`     | Matrix (Nl × Nw) | Linear constraint matrix for the circuit                   |
| `Wm`     | Matrix (Nm × Nw) | Multiplicative constraint matrix for the circuit           |
| `al`     | Vector (Nl)      | Constant vector for linear constraints                     |
| `am`     | Vector (Nm)      | Constant vector for multiplicative constraints             |
| `fl`     | Binary flag      | Whether input vectors appear in linear constraints         |
| `fm`     | Binary flag      | Whether input vectors appear in multiplicative constraints |

## Witness Vectors

| Variable | Type        | Description                                |
| -------- | ----------- | ------------------------------------------ |
| `wL`     | Vector (Nm) | Left inputs to multiplication gates        |
| `wR`     | Vector (Nm) | Right inputs to multiplication gates       |
| `wO`     | Vector (NO) | Output witness vector                      |
| `wV`     | Vector      | Concatenation of all circuit input vectors |
| `w`      | Vector (Nw) | Combined witness: `w = wL‖wR‖wO`           |

## Dimensions

| Variable | Description                            |
| -------- | -------------------------------------- |
| `Nm`     | Number of multiplication gates         |
| `Nl`     | Number of linear constraints           |
| `NO`     | Length of output witness vector `wO`   |
| `Nv`     | Length of each input vector            |
| `Nw`     | Total witness length: `Nw = 2*Nm + NO` |
| `k`      | Number of input vectors                |

## Commitment Structure

| Variable | Type          | Description                         |
| -------- | ------------- | ----------------------------------- |
| `CL`     | Group element | Commitment to left witness          |
| `CR`     | Group element | Commitment to right witness         |
| `CO`     | Group element | Commitment to output witness        |
| `CS`     | Group element | Commitment for blinding/error terms |
| `Vi`     | Group element | Commitment to input vector `i`      |

## Partition Function & Layout

| Variable         | Type         | Description                                      |
| ---------------- | ------------ | ------------------------------------------------ |
| `F`              | Function     | Maps each `wO[i]` to position in `{lO,lL,lR,nO}` |
| `lL, lR, lO`     | Vectors (Nv) | Linear parts of witness layout                   |
| `nL, nR, nO`     | Vectors (Nm) | Norm parts of witness layout (`nL=wL, nR=wR`)    |
| `rL, rR, rO, rS` | Vectors (8)  | Blinding vectors for error terms                 |

## Redistributed Matrices

| Variable | Type   | Description                                            |
| -------- | ------ | ------------------------------------------------------ |
| `Ma,n,L` | Matrix | Part of `Wa` acting on `wL` (left inputs)              |
| `Ma,n,R` | Matrix | Part of `Wa` acting on `wR` (right inputs)             |
| `Ma,n,O` | Matrix | Part of `Wa` acting on `nO` (outputs in norm part)     |
| `Ma,l,L` | Matrix | Part of `Wa` acting on `lL` (outputs in linear part L) |
| `Ma,l,R` | Matrix | Part of `Wa` acting on `lR` (outputs in linear part R) |
| `Ma,l,O` | Matrix | Part of `Wa` acting on `lO` (outputs in linear part O) |

## Challenges (Verifier randomness)

| Variable | Description                                  |
| -------- | -------------------------------------------- |
| `λ`      | Linear combination challenge for constraints |
| `μ`      | Multiplicative challenge (μ = ρ²)            |
| `ρ`      | Challenge for norm linear argument           |
| `β`      | Challenge for blinding error terms           |
| `δ`      | Challenge separating commitments             |
| `τ`      | Evaluation point for polynomial commitment   |
| `α`      | Challenge for reciprocal arguments           |
| `γ`      | Challenge for norm linear argument reduction |

## Polynomial Commitments

| Variable | Type       | Description                  |
| -------- | ---------- | ---------------------------- |
| `v(T)`   | Polynomial | Value polynomial             |
| `l(T)`   | Polynomial | Linear constraint polynomial |
| `n(T)`   | Polynomial | Norm polynomial              |
| `c(T)`   | Polynomial | Constraint vector polynomial |
| `f(T)`   | Polynomial | Main verification polynomial |

## Cryptographic Setup

| Variable | Type                     | Description                     |
| -------- | ------------------------ | ------------------------------- |
| `G`      | Group element            | Generator for value commitments |
| `G`      | Vector of group elements | Generators for norm part        |
| `H`      | Vector of group elements | Generators for linear part      |
| `p`      | Prime                    | Order of the group/field        |
| `F`      | Field                    | Finite field Fp                 |

This should serve as a handy reference while reading through the protocol!