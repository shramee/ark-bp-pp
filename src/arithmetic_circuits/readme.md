# Bulletproofs++ Protocol Documentation

As describe in section 5 Arithmetic Circuits of [EKRN23](../../papers/2022-510-bulletproofs-plus-plus.pdf).

# Bulletproofs++ Protocol Documentation

## 1. Arithmetic Circuit Protocol
#### Implemented in [mod.rs](./mod.rs)
From section **5.3 Full Protocol Description** (of **5 Arithmetic circuits**),

**Protocol**: Arithmetic Circuit Protocol $`\langle\mathcal{P}_{ac}, \mathcal{V}_{ac}\rangle`$

**Common input**: $`G \in \mathbb{G}`$, $`\mathbf{G} \in \mathbb{G}^{N_m}`$, $`\mathbf{H} \in \mathbb{G}^{N_v+7}`$, $`\mathbf{W}_m \in \mathbb{F}^{N_m \times N_w}`$, $`\mathbf{a}_m \in \mathbb{F}^{N_m}`$, $`\mathbf{W}_l \in \mathbb{F}^{N_l \times N_w}`$, $`\mathbf{a}_l \in \mathbb{F}^{N_l}`$, $`f_l, f_m \in \{0, 1\}`$, $`\mathbf{V} \in \mathbb{G}^k`$

**$`\mathcal{P}`$'s input**: $`\mathbf{v}_i \in \mathbb{F}^{N_v}`$, $`s_V \in \mathbb{F}^k`$, $`\mathbf{w}_L, \mathbf{w}_R \in \mathbb{F}^{N_m}`$, $`\mathbf{w}_O \in \mathbb{F}^{N_O}`$, $`\mathcal{F} : [0 .. N_O - 1] \to (\{l_O, l_L, l_R\} \times [0 .. N_v - 1]) \cup (\{n_O\} \times [0 .. N_O - 1])`$

1. $`\mathcal{P}`$ computes:

$$r_O, r_L, n_O, n_L, l_O, l_L, C_O, C_L := \text{CommitOL}(w_O, w_L, \mathcal{F})$$
$$r_R, n_R, l_R, C_R := \text{CommitR}(w_O, w_R, \mathcal{F})`$$

2. $`\mathcal{P}, \mathcal{V}`$ run the Inner Arithmetic Circuit protocol $`\langle\mathcal{P}_{iac}, \mathcal{V}_{iac}\rangle`$.

## 2. CommitOL Subroutine
#### Implemented in [commit.rs](./commit.rs)
From section **5.3 Full Protocol Description** (of **5 Arithmetic circuits**),

**Input**: $`w_O, w_L, \mathcal{F}`$

$`r'_O \xleftarrow{\$} \mathbb{F}^6, r'_L \xleftarrow{\$} \mathbb{F}^5`$

$`r_O := (r'_{O,0}, r'_{O,1}, r'_{O,2}, r'_{O,3}, 0, r'_{O,4}, r'_{O,5}, 0) \in \mathbb{F}^8`$

$`r_L := (r'_{L,0}, r'_{L,1}, r'_{L,2}, 0, r'_{L,3}, r'_{L,4}, 0, 0) \in \mathbb{F}^8`$

$`n_L := w_L \in \mathbb{F}^{N_m}`$

Let $`n_O \in \mathbb{F}^{N_m}`$ such that $`n_{O,j} := \begin{cases} w_{O,i} & \text{if } \mathcal{F}^{-1}(n_O, j) = i \\ 0 & \text{otherwise} \end{cases}`$

Let $`l_X \in \mathbb{F}^{N_v}`$ for $`X = L, O`$ such that
$`l_{X,j} := \begin{cases} w_{O,i} & \text{if } \mathcal{F}^{-1}(l_X, j) = i \\ 0 & \text{otherwise} \end{cases}`$

$`C_X := r_{X,0}G + \langle r_{X,1:}||l_X, \mathbf{H}\rangle + \langle n_X, \mathbf{G}\rangle \in \mathbb{G} \text{ for } X = L, O`$

Return $`r_O, r_L, n_O, n_L, l_O, l_L, C_O, C_L`$

## 3. CommitR Subroutine
#### Implemented in [commit.rs](./commit.rs)
From section **5.3 Full Protocol Description** (of **5 Arithmetic circuits**),

**Input**: $`w_O, w_R, \mathcal{F}`$

$`r'_R \xleftarrow{\$} \mathbb{F}^4`$

$`r_R := (r'_{R,0}, r'_{R,1}, 0, r'_{R,2}, r'_{R,3}, 0, 0, 0) \in \mathbb{F}^8`$

$`n_R := w_R \in \mathbb{F}^{N_m}`$

Let $`l_R \in \mathbb{F}^{N_v}`$ such that
$`l_{R,j} := \begin{cases} w_{O,i} & \text{if } \mathcal{F}^{-1}(l_R, j) = i \\ 0 & \text{otherwise} \end{cases}`$

$`C_R := r_{R,0}G + \langle r_{R,1:}||l_R, \mathbf{H}\rangle + \langle n_R, \mathbf{G}\rangle \in \mathbb{G}`$

Return $`r_R, n_R, l_R, C_R`$

## 4. Inner Arithmetic Circuit Protocol
#### Implemented in [inner_circuit.rs](./inner_circuit.rs)
From section **5.3 Full Protocol Description** (of **5 Arithmetic circuits**),

**Protocol**: Inner Arithmetic Circuit Protocol $`\langle\mathcal{P}_{iac}, \mathcal{V}_{iac}\rangle`$

**Common input**: Same as the Arithmetic Circuit Protocol

**$`\mathcal{P}`$'s input**: Same as the Arithmetic Circuit Protocol and $`r_X \in \mathbb{F}^8`$, $`n_X \in \mathbb{F}^{N_m}`$, $`l_X \in \mathbb{F}^{N_v}`$, $`C_X \in \mathbb{G}`$ for $`X = L, R, O`$

1. $`\mathcal{P} \to \mathcal{V}`$: $`C_L, C_R, C_O`$

2. $`\mathcal{V} \to \mathcal{P}`$: $`\rho, \lambda, \beta, \delta \xleftarrow{\$} \mathbb{F}`$

3. $`\mathcal{P}, \mathcal{V}`$ compute:

$`M_{a,n,L} := (\mathbf{W}_{a,i,j})_{0 \leq j \leq N_m-1} \in \mathbb{F}^{N_a \times N_m} \text{ for } a = l, m`$

$`M_{a,n,R} := (\mathbf{W}_{a,i,j})_{N_m \leq j \leq 2N_m-1} \in \mathbb{F}^{N_a \times N_m} \text{ for } a = l, m`$

$`\mathbf{W}_{a,O} := (\mathbf{W}_{a,i,j})_{2N_m \leq j \leq N_w-1} \in \mathbb{F}^{N_a \times N_O} \text{ for } a = l, m`$

Let $`M_{a,n,O} \in \mathbb{F}^{N_a \times N_m}`$ for $`a = l, m`$ such that
$`M_{a,n,O,j',j} := \begin{cases} (\mathbf{W}_{a,O,j',i}) & \text{if } \mathcal{F}^{-1}(n_O, j) = i \\ 0 & \text{otherwise} \end{cases}`$

Let $`M_{a,l,X} \in \mathbb{F}^{N_a \times N_v}`$ for $`a = l, m`$, $`X = L, R, O`$ such that
$`M_{a,l,X,j',j} := \begin{cases} (\mathbf{W}_{a,O,j',i}) & \text{if } \mathcal{F}^{-1}(l_X, j) = i \\ 0 & \text{otherwise} \end{cases}`$

$`\mu := \rho^2 \in \mathbb{F}`$

$`\hat{V} := 2\sum_{i=0}^{k-1} (f_l \lambda^{N_v i} + f_m \mu^{N_v i+1})V_i \in \mathbb{G}`$

$`\boldsymbol{\lambda} := e_{N_l}(\lambda) - f_l f_m (\mu e_{N_v}(\lambda) \otimes e_k(\mu^{N_v}) + e_{N_v}(\mu) \otimes e_k(\lambda^{N_v})) \in \mathbb{F}^{N_l}`$

$`\boldsymbol{\mu} := \mu e_{N_m}(\mu) \in \mathbb{F}^{N_m}`$

For $`X = L, R, O`$:
$`c_{n,X} := (\boldsymbol{\lambda}^T M_{l,n,X} + \boldsymbol{\mu}^T M_{m,n,X}) \text{diag}(\mu)^{-1} \in \mathbb{F}^{N_m}`$

$`c_{l,X} := \boldsymbol{\lambda}^T M_{l,l,X} + \boldsymbol{\mu}^T M_{m,l,X} \in \mathbb{F}^{N_v}`$

$`p_n(T) := \delta^{-1}T^3 c_{n,O} + T^2 c_{n,L} + T c_{n,R} \in \mathbb{F}^{N_m}[T]`$

$`p_s(T) := |p_n(T)|^2_\mu + \langle\boldsymbol{\lambda}, \mathbf{a}_l\rangle T^3 + \langle\boldsymbol{\mu}, \mathbf{a}_m\rangle T^3 \in \mathbb{F}[T]`$

4. $`\mathcal{P}`$ computes:

$`l_S \xleftarrow{\$} \mathbb{F}^{N_v}`$

$`n_S \xleftarrow{\$} \mathbb{F}^{N_m}`$

$`\hat{v} := 2\sum_{i=0}^{k-1} (f_l \lambda^{N_v i} + f_m \mu^{N_v i+1})v_{i,0} \in \mathbb{F}`$

$`\hat{c}_l(T) := 2(\delta^{-1}T^3 c_{l,O} + T^2 c_{l,L} + T c_{l,R}) + f_m \mu e_{N_v}(\mu)_{1:} + f_l e_{N_v}(\lambda)_{1:} \in \mathbb{F}^{N_v}[T]`$

$`\hat{l}(T) := T^{-1} l_S + \delta l_O + T l_L + T^2 l_R + T^3 (2\sum_{i=0}^{k-1} (f_l \lambda^{N_v i} + f_m \mu^{N_v i+1})v_{i,1:}) \in \mathbb{F}^{N_v}[T]`$

$`\hat{n}(T) := T^{-1} n_S + \delta n_O + T n_L + T^2 n_R \in \mathbb{F}^{N_m}[T]`$

$`n(T) := p_n(T) + \hat{n}(T) \in \mathbb{F}^{N_m}[T]`$

$`\hat{f}(T) := p_s(T) + \hat{v}T^3 - \langle\hat{c}_l(T), \hat{l}(T)\rangle - |n(T)|^2_\mu \in \mathbb{F}^8[T]`$

Let $`\hat{\mathbf{f}} \in \mathbb{F}^8`$ be the vector of coefficients of $`\hat{f}(T)`$

$`r_V = (0, 2\sum_{i=0}^{k-1} (f_l \lambda^{N_v i} + f_m \mu^{N_v i+1})s_{V,i}, 0, \ldots, 0) \in \mathbb{F}^8`$

$`s_r := (\beta\delta r_{O,1}, 0, \beta^{-1}\delta r_{O,0} + r_{L,1}, \delta r_{O,2} + \beta^{-1}r_{L,0} + r_{R,1}, \delta r_{O,3} + r_{L,2} + r_{V,1} + \beta^{-1}r_{R,0}, r_{L,4} + r_{R,3}, \delta r_{O,5} + r_{R,4}, \delta r_{O,6} + r_{L,5}) \in \mathbb{F}^8`$

$`r_S := (\hat{f}_0||\beta^{-1}\hat{\mathbf{f}}_{1:}) - s_r`$

$`C_S := r_{S,0}G + \langle r_{S,1:}||l_S, \mathbf{H}\rangle + \langle n_S, \mathbf{G}\rangle \in \mathbb{G}`$

5. $`\mathcal{P} \to \mathcal{V}`$: $`C_S`$

6. $`\mathcal{V} \to \mathcal{P}`$: $`\tau \xleftarrow{\$} \mathbb{F}`$

7. $`\mathcal{P}`$ computes:

$`r(T) := T^{-1}r_S + \delta r_O + T r_L + T^2 r_R + T^3 r_V \in \mathbb{F}^8[T]`$

$`v(T) := p_s(T) + \hat{v}T^3 + r_0(T) \in \mathbb{F}[T]`$

$`l(T) := r_{1:}(T)||\hat{l}(T) \in \mathbb{F}^{7+N_v}[T]`$

8. $`\mathcal{P}, \mathcal{V}`$ compute:

$`P(T) := p_s(T)G + \langle p_n(T), \mathbf{G}\rangle \in \mathbb{G}[T]`$

$`\hat{c}_r(T) := (1, \beta T^{-1}, \beta T, \beta T^2, \beta T^3, \beta T^5, \beta T^6, \beta T^7) \in \mathbb{F}^8[T]`$

$`c(T) := \hat{c}_{r,1:}(T)||\hat{c}_l(T) \in \mathbb{F}^{7+N_v}[T]`$

$`C(T) := P(T) + T^{-1}C_S + \delta C_O + T C_L + T^2 C_R + T^3 \hat{V} \in \mathbb{G}[T]`$

9. $`\mathcal{P}, \mathcal{V}`$ run the weighted norm linear argument $`\langle\mathcal{P}_{nl}, \mathcal{V}_{nl}\rangle = b`$ with common input $`(G, \mathbf{G}, \mathbf{H}, c(\tau), C(\tau), \mu = \rho^2)`$ and prover input $`(l(\tau), n(\tau), v(\tau))`$.