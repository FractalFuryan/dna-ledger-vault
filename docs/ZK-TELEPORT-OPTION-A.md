# Halo2 Teleport Proof — Option A (Field-valid Spec)

⭕️🛑 **Public-safe ZK spec**
This is a rigorous circuit-level specification. All operations are field-valid. No undefined arithmetic.

---

## Goal

Prove there exists a chain of scalars $(k_0, k_1, \ldots, k_m \in \mathbb{F}_r)$ such that:

- $Q_i = k_i \cdot G$ for each step
- $k_{i+1} = \texttt{teleport}(k_i, s_i, z_i)$ (mixing rule)
- Final: $Q_m = Q_{\text{target}}$

---

## Public inputs

- $Q_0 = (x_0, y_0)$ — initial point
- $Q_{\text{target}} = (x_T, y_T)$ — target point
- $m$ — number of steps (compile-time constant preferred)
- Ancilla seeds: $s_0, s_1, \ldots, s_{m-1}$ (16-bit each, public or committed)
- Optional: redshift indices $r_i$ or discretized $z_i$ per step

**Note:** Keep $m$ fixed (e.g., 8 or 16) for static circuit size.

---

## Witnesses (per step i)

- Scalar $k_i \in \mathbb{F}_r$
- 16 limbs: $k_{i,j}$ for $j \in [0, 15]$, each 16-bit
- Mixed/rotated limbs as needed
- Optional: selector bit $b_i \in \{0,1\}$ for hybrid local+teleport

---

## Prohibited in-circuit operations

❌ No floats, no real arithmetic  
❌ No `abs`, `floor`, `sqrt`  
❌ No "probability claims" ("randomness happened")  
❌ No symbolic GR redshift math in-circuit  
❌ No permutation argument (not needed for linear chain)  

---

## Core: Limb-based teleport (field-valid)

### Step 1: Limb decomposition constraint

Represent:
$$k_i = \sum_{j=0}^{15} k_{i,j} \cdot 2^{16j}$$

**Constraints:**
- Each $k_{i,j}$ is 16-bit (range check / lookup)
- Recomposition equals scalar $k_i$ inside the field

This is standard in Halo2: "decompose scalar into small limbs."

---

### Step 2: U16 matrix multiply

Let $v_i \in (\mathbb{Z}_{2^{16}})^{16}$ be the limb vector of $k_i$ where $v_i[j] = k_{i,j}$.

Compute:
$$w_i = U16 \cdot v_i \pmod{2^{16}}$$

**Constraints:**
- Each output limb computed via gate:
  $$w_i[j] = \sum_{t=0}^{15} U16[j,t] \cdot v_i[t] \pmod{2^{16}}$$
- Constrain each $w_i[j]$ is 16-bit
- Handle carries via range constraints or lookup-based bounds

---

### Step 3: XOR gate (16-bit lookup)

Apply ancilla XOR to limbs:
$$u_i[j] = w_i[j] \oplus s_i \quad \text{for } j \in S$$

**Constraints:**
- XOR via lookup table mapping $(a,b) \mapsto a \oplus b$ for 16-bit values
- Can XOR single limb or multiple limbs for stronger mixing

---

### Step 4: Redshift/scaling (discretized, lookup-only)

Instead of symbolic probability, use deterministic scaling on limbs:

$$u_i[0] := (u_i[0] \cdot (1 + \gamma z_i^2)) \bmod 2^{16}$$

Where:
- $z_i$ is small integer or fixed-point from lookup table
- $\gamma$ is fixed-point constant
- Compute with bounded polynomial gate
- Range-check output to 16-bit

**Purpose:** "Higher curvature → bigger jump magnitude" (deterministic, no probability comparison)

---

### Step 5: Recompose next scalar

$$k_{i+1} = \sum_{j=0}^{15} u_i[j] \cdot 2^{16j}$$

**Constraints:**
- Range check each $u_i[j]$ (16-bit)
- Recomposition equals witness scalar $k_{i+1}$

**This is your teleport_share entirely inside the circuit, well-defined.**

---

## EC constraints (halo2-ecc)

For each step:
$$Q_i = k_i \cdot G$$

- Constrain $Q_0$ equals public input
- Constrain $Q_m$ equals $Q_{\text{target}}$
- **One scalar multiplication per step** (not two)

---

## Hybrid local + teleport (optional)

For mixed local/teleport steps:

**Add witness bit $b_i$:**
- Compute both candidates:
  - Local: $k_{i+1}^{(L)} = F(k_i)$
  - Teleport: $k_{i+1}^{(T)} = \texttt{teleport}(k_i, s_i, z_i)$
  
**Select:**
$$k_{i+1} = b_i \cdot k_{i+1}^{(T)} + (1-b_i) \cdot k_{i+1}^{(L)}$$

**Constraint:**
$$b_i(b_i - 1) = 0$$

This is the correct ZK way to represent a branch.

---

## Minimal step summary (one-liner)

Per step $i$:  
**Decompose $k_i$ → U16 mix limbs → XOR with $s_i$ → optional redshift scaling → recompose $k_{i+1}$ → enforce $Q_i = k_i \cdot G$**

---

## Chaining constraint

Finally:
$$Q_m = Q_{\text{target}}$$

This yields a proof that the evolution rules were followed correctly across $m$ steps.

---

## Engineering TODO (for implementation)

- [ ] Choose limb width (u16 vs smaller slices for XOR lookup)
- [ ] Implement lookup tables for XOR (16-bit)
- [ ] Implement lookup tables for redshift scaling (fixed-point)
- [ ] Define fixed-point scaling convention
- [ ] Implement branch gate constraints for selector bits
- [ ] Ensure sound range constraints for all limbs
- [ ] Choose EC scalar multiplication gadget (halo2-ecc native)
- [ ] Set circuit size (recommend $m \in \{8, 16\}$ for static layout)

---

## Deleted from previous spec (for rigor)

- ❌ `floor(|…|)` / `abs` operations
- ❌ "Probability happened" language
- ❌ Permutation argument (not needed)
- ❌ Duplicate P/Q scalar-muls
- ❌ Symbolic physics computations
