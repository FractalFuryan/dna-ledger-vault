# enhanced_F_k — State Mixer Notes (v2)

⭕️🛑 **Public-safe math + classification**

## Formal definition

`enhanced_F_k` is a **nonlinear, stochastic state-transition operator on a finite ring** with optional nonlocal jumps.

Formally:
$$k_{t+1} = F(k_t; \theta) \bmod n$$

## Classification

**One-line summary:**
> A nonlinear, entropy-salted modular state mixer with rare nonlocal jumps, designed to preserve structured unpredictability while avoiding phase trapping.

**Technical classification:**
- Nonlinear modular dynamical system
- Chaotic state mixer with replica-coupled stochastic maps
- NOT a PRNG, optimizer, or formal cryptographic primitive

## Structural components

### 1) Biased walk on $\mathbb{Z}_n$
A modular random walk with state-dependent drift. Not memoryless: $J(k)$ feeds back into step size.

### 2) Nonlinear feedback (cubic term)
Adds controlled instability:
- Linear term → smooth bias
- Cubic term → local divergence
- Produces bounded chaos under modulo folding

### 3) Redshift scaling
A slow, global modifier acting like adiabatic drift or annealing context scaling. Prevents strict stationarity.

### 4) Teleportation branch
Rare, discontinuous jumps that:
- break locality
- prevent trapping in invariant tori
- analogous to replica exchange or nonlocal Monte Carlo moves

### 5) Entropy injection (ancilla)
Entropy gates **routing**, not the base law. Adds unpredictability without degenerating to pure noise.

## v2 strengthening (what's better)

### 1) Deterministic ancilla chain
```
ancilla16(seed, t, domain) = SHA256(seed || domain || t)[:2]
```
Replaces global RNG with reproducible entropy source. No external state required.

### 2) Dual-phase drift
- **Primary drift:** $\Delta_j = J(k) \cdot \alpha \cdot (1 + z)$
- **Orthogonal drift:** $\Delta_b = J_b(k) \cdot \alpha_2 \cdot (1 + z)$
- $J_b(k)$ derived via independent mixer (e.g., SplitMix64-style hash)
- Goal: reduce structural predictability, prevent resonance trapping

### 3) State-aware teleport probability (stateless)
```
p_tp(k, Ja, Jb) = p0 + β(1 - H(Ja ⊕ Jb ⊕ k))
```
Where $H(x)$ is local entropy proxy (bit population balance). Higher probability when mixing looks "too structured," but uses **no history**.

### 4) Deterministic teleport gating
```
do_tp = (ancilla16(seed, t) / 65535) < p_tp(k, Ja, Jb)
```
Fully reproducible under audit. Same $(seed, t, k)$ → same teleport decision.

### 5) Bounded constraints
- $p_{\text{min}} \leq p_{tp} \leq p_{\text{max}}$ (e.g., $[0.01, 0.15]$)
- All operations modulo $n$ (no unbounded growth)
- All shifts/scales use fixed-point integer arithmetic

### 6) Optional CSPRNG salt (routing-only)
```
anc = deterministic_ancilla XOR os.urandom(2)
```
Allowed **only** if it affects routing/jump selection, never the base transition law.

## Audit-grade test requirements

Required properties:
1. **Determinism:** Same inputs → same output (given fixed seed)
2. **Avalanche:** Single bit seed change → likely different output
3. **Bounded teleport:** $p_{tp}$ always within configured bounds
4. **No memory:** No state accumulation across calls beyond $(k, t)$

## Non-negotiable rule

Entropy affects routing/jumps — **not** personalization, memory, or convergence optimization.
