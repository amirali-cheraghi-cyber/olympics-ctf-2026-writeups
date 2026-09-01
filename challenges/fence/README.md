# FENCE

**OLYMPICS CTF 2026 — Cryptography**

| Field          | Value                     |
| -------------- | ------------------------- |
| Challenge      | FENCE                     |
| Category       | Cryptography              |
| Main Technique | NTRU-style Lattice Attack |
| Ring           | `Z_q[x] / (x^128 + 1)`    |
| `n`            | `128`                     |
| `q`            | `268435361`               |
| Secret Weight  | `80`                      |
| Main Tools     | Python, fpylll, LLL, BKZ  |
| Status         | Solved                    |

---

## 1. Overview

FENCE is a lattice-based cryptography challenge built around polynomial arithmetic in a negacyclic ring.

The challenge exposes several public polynomials derived from small secret polynomials. Although the cryptographic construction uses SHA3-256, SHAKE-256 and HMAC-SHA256, none of these primitives need to be broken directly.

The critical weakness is the structure of the secret polynomials:

```text
coefficients ∈ {-1, 0, +1}
weight = 80
```

This makes the secret pair unusually short when represented as a lattice vector.

The attack therefore consists of recovering the secret polynomials using lattice reduction and then reproducing the challenge's key derivation and decryption process.

The complete attack chain is:

```text
Public polynomial H
        │
        ▼
Negacyclic multiplication matrix
        │
        ▼
NTRU-style lattice
        │
        ▼
LLL reduction
        │
        ▼
BKZ reduction if necessary
        │
        ▼
Recover secret (a, b)
        │
        ▼
Verify a · H = b
        │
        ▼
Derive SHA3-256 key
        │
        ▼
Verify HMAC-SHA256
        │
        ▼
Generate SHAKE-256 keystream
        │
        ▼
Decrypt five ciphertexts
        │
        ▼
M0 ⊕ M1 ⊕ M2 ⊕ M3 ⊕ M4
        │
        ▼
      FLAG
```

---

# 2. Challenge Parameters

The important parameters from the challenge implementation are:

```python
n = 128
q = 268435361
w = 80
```

The polynomial ring is:

```text
R = Z_q[x] / (x^128 + 1)
```

Therefore:

```text
x^128 = -1
```

The secret polynomials have 128 coefficients and satisfy:

```text
a_i ∈ {-1, 0, +1}
b_i ∈ {-1, 0, +1}
```

with exactly 80 non-zero coefficients:

```text
weight(a) = 80
weight(b) = 80
```

This small coefficient space is the central weakness.

---

# 3. Understanding the Polynomial Operations

The challenge implements its own polynomial arithmetic.

The relevant operations are:

```text
tr()  → remove trailing zero coefficients
sb()  → polynomial subtraction
ml()  → polynomial multiplication
dv()  → polynomial division
iv()  → polynomial inversion
pm()  → negacyclic multiplication
sh()  → negacyclic rotation
```

All operations are performed modulo:

```text
q = 268435361
```

The important multiplication function is `pm()`.

Conceptually:

```text
c = a · b mod (x^128 + 1, q)
```

The implementation handles coefficients that wrap around degree 127 by negating them:

```python
if i + j < n:
    c[i + j] = (c[i + j] + a[i] * b[j]) % q
else:
    c[i + j - n] = (c[i + j - n] - a[i] * b[j]) % q
```

The subtraction occurs because:

```text
x^128 = -1
```

This is a negacyclic convolution.

---

# 4. The Critical Algebraic Relation

The public polynomial is related to two secret polynomials by:

```text
h = b · a^(-1) mod q
```

Multiplying both sides by `a` gives:

```text
a · h = b mod q
```

This is the relation we exploit.

The important observation is that `h` is public, while `a` and `b` are secret but extremely small:

```text
a, b ∈ {-1, 0, +1}^128
```

with weight 80.

Therefore, the secret pair `(a,b)` corresponds to a very short vector satisfying a publicly known modular relation.

This is exactly the type of structure that can be attacked with lattice reduction.

---

# 5. Centered Representation

The solver represents coefficients using centered representatives.

```python
def center(x, q):
    x %= q

    if x > q // 2:
        x -= q

    return x
```

Instead of representing a coefficient close to `q` as a large positive integer, it is represented as a small negative integer.

For example:

```text
q - 1  →  -1
q - 2  →  -2
```

This is important because lattice algorithms search for short vectors.

---

# 6. Converting Polynomial Multiplication to a Matrix

The equation:

```text
a · h = b mod q
```

can be represented using a matrix describing multiplication by `h`.

For a polynomial:

```text
h = h0 + h1x + ... + h127x^127
```

we construct a `128 × 128` negacyclic multiplication matrix `H`.

The solver implements:

```python
def negacyclic_matrix(h):
    H = [[0] * N for _ in range(N)]

    for i in range(N):
        for j in range(N):
            k = i + j

            if k < N:
                H[i][k] = center(h[j])
            else:
                H[i][k - N] = center(-h[j])

    return H
```

This matrix represents multiplication by `h` inside:

```text
Z_q[x] / (x^128 + 1)
```

so that the polynomial relation can be treated as an integer matrix relation.

---

# 7. Constructing the NTRU-style Lattice

The main lattice has the form:

```text
       ┌ I   H ┐
M  =   │       │
       └ 0   qI┘
```

where:

```text
I  = 128 × 128 identity matrix
H  = negacyclic multiplication matrix
qI = q multiplied by the identity matrix
```

The resulting lattice dimension is:

```text
2 × 128 = 256
```

The solver builds it with:

```python
def build_lattice(h):
    M = IntegerMatrix(2 * N, 2 * N)

    for i in range(N):
        M[i, i] = 1

        for j in range(N):
            k = i + j

            if k < N:
                M[i, N + k] = center(h[j])
            else:
                M[i, N + k - N] = center(-h[j])

        M[N + i, N + i] = Q

    return M
```

Because:

```text
a · H ≡ b (mod q)
```

there exists an integer vector `k` such that:

```text
aH - b = qk
```

Therefore the secret pair is embedded into the lattice.

---

# 8. Why the Secret Can Be Recovered

A normal lattice vector can contain very large coefficients because:

```text
q = 268435361
```

The secret, however, consists only of:

```text
-1
 0
+1
```

with exactly 80 non-zero coefficients per polynomial.

Consequently, the secret vector is unusually short compared with generic lattice vectors.

LLL attempts to transform the basis into a reduced basis containing short vectors.

If LLL does not reveal the secret directly, BKZ is used to perform stronger lattice reduction.

---

# 9. LLL Reduction

The first attack uses LLL:

```python
LLL.reduction(M)
```

The process is:

```text
Build lattice
      ↓
LLL reduction
      ↓
Inspect short vectors
      ↓
Check ternary structure
```

After reduction, each candidate row is split into:

```text
a = row[:128]
b = row[128:]
```

The candidate is then checked against the expected secret structure.

---

# 10. Detecting the Secret Vector

The solver requires every coefficient to be one of:

```text
{-1, 0, +1}
```

and exactly 80 coefficients must be non-zero.

The validation function is:

```python
def is_pm01(vec, w=80):
    nz = 0

    for x in vec:
        if x not in (-1, 0, 1):
            return False

        if x != 0:
            nz += 1

    return nz == w
```

This gives us a very strong distinguisher.

A candidate is accepted only if:

```text
all coefficients ∈ {-1,0,+1}
```

and:

```text
number of non-zero coefficients = 80
```

for both halves.

---

# 11. BKZ Fallback

If LLL does not expose the secret vector, the solver performs BKZ reduction.

The main solver uses:

```text
BKZ-20
BKZ-30
BKZ-40
```

The experimental implementation `ntru_bkz.py` additionally tries:

```text
BKZ-50
BKZ-60
```

The idea is to progressively increase the reduction strength until the short secret vector becomes visible.

The trade-off is:

```text
larger block size
        ↓
stronger reduction
        ↓
higher computational cost
```

---

# 12. Verifying the Recovered Key

A ternary vector with weight 80 is not enough.

The solver verifies the algebraic relation against the original public polynomial.

It computes:

```python
prod = pm(a, h)
prod_c = [center(x) for x in prod]
```

and checks:

```text
a · h = b
```

It also accepts the globally negated vector:

```text
a · h = -b
```

because lattice reduction can return either:

```text
(a,b)
```

or:

```text
(-a,-b)
```

The solver also checks the swapped relation to handle orientation:

```text
b · h = a
```

This prevents an arbitrary short vector from being accepted.

---

# 13. Sign and Orientation Handling

Lattice reduction has a natural sign ambiguity.

If:

```text
v
```

is a valid lattice vector, then:

```text
-v
```

is also a valid lattice vector.

Therefore the solver tries:

```text
(a, b)
(-a, -b)
```

and also the swapped forms:

```text
(b, a)
(-b, -a)
```

The implementation is:

```python
for aa, bb in (
    (a, b),
    ([-x for x in a], [-x for x in b]),
    (b, a),
    ([-x for x in b], [-x for x in a]),
):
    ...
```

The HMAC verification ultimately determines whether a candidate produces the correct cryptographic state.

---

# 14. Key Derivation

After recovering `(a,b)`, the challenge derives a symmetric key.

The relevant function is:

```python
def ky(a, b, s):
    u = min(
        tuple(sh(a, i) + sh(b, i))
        for i in range(2 * n)
    )

    return hashlib.sha3_256(
        d + s + bytes(i + 1 for i in u)
    ).digest()
```

The hash function is:

```text
SHA3-256
```

The key derivation depends on:

```text
challenge constant d
secret polynomials
salt/parameter s
```

The challenge therefore does not directly use the recovered polynomials as an AES key.

Instead, they are fed into the challenge's custom key derivation function.

---

# 15. HMAC Verification

Each encrypted record contains:

```text
S
C
T
```

where:

```text
S = challenge parameter
C = ciphertext
T = authentication tag
```

The authenticated metadata is serialized deterministically:

```python
u = json.dumps(
    {"N": n, "Q": q, "H": h},
    sort_keys=True,
    separators=(",", ":")
).encode()
```

The solver then checks:

```python
hmac.compare_digest(
    t,
    hmac.new(
        k,
        d + u + s + c,
        hashlib.sha256
    ).digest()[:16]
)
```

The authentication algorithm is:

```text
HMAC-SHA256
```

with a 16-byte truncated tag.

This provides an additional verification mechanism for the recovered secret.

---

# 16. Decryption

Once the HMAC is valid, the ciphertext is decrypted using a SHAKE-256-generated keystream.

The keystream is:

```python
zstream = hashlib.shake_256(
    d + k + s
).digest(len(c))
```

The ciphertext is then XORed with the keystream:

```python
return bytes(
    i ^ j
    for i, j in zip(c, zstream)
)
```

Therefore:

```text
plaintext = ciphertext XOR SHAKE256(d || k || s)
```

No block cipher is required at this stage.

---

# 17. Recovering the Five Messages

The challenge contains five encrypted records.

The main solver performs the attack for:

```text
H[0]
H[1]
H[2]
H[3]
H[4]
```

For each record:

```text
        H[i]
         │
         ▼
  Build lattice
         │
         ▼
       LLL
         │
         ├── Success
         │
         └── BKZ
              │
              ▼
       Recover (a,b)
              │
              ▼
        Verify relation
              │
              ▼
        Derive key
              │
              ▼
        Verify HMAC
              │
              ▼
          Decrypt
```

Only after all five messages have been successfully decrypted does the final XOR take place.

---

# 18. Final Flag Construction

The five plaintexts are XORed byte-by-byte:

```python
flag = bytes(
    msgs[0][j]
    ^ msgs[1][j]
    ^ msgs[2][j]
    ^ msgs[3][j]
    ^ msgs[4][j]
    for j in range(len(msgs[0]))
)
```

In mathematical form:

```text
FLAG = M0 ⊕ M1 ⊕ M2 ⊕ M3 ⊕ M4
```

The resulting flag is written to:

```text
flag.txt
```

and printed by the solver.

---

# 19. Reproducing the Solve

## Requirements

The solver requires:

```text
Python 3
fpylll
```

The remaining modules are part of Python's standard library:

```text
json
time
hashlib
hmac
sys
```

---

## 19.1 Enter the Challenge Directory

From the repository root:

```bash
cd challenges/fence
```

Check the directory:

```bash
ls -la
```

The expected structure is:

```text
fence/
├── README.md
└── solver/
    ├── solve.py
    ├── ntru_attack.py
    └── ntru_bkz.py
```

---

## 19.2 Create a Virtual Environment

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Verify Python:

```bash
python3 --version
```

---

## 19.3 Install Dependencies

Upgrade pip:

```bash
python3 -m pip install --upgrade pip
```

Install `fpylll`:

```bash
python3 -m pip install fpylll
```

Verify the installation:

```bash
python3 -c "from fpylll import IntegerMatrix, LLL, BKZ; print('fpylll OK')"
```

Expected:

```text
fpylll OK
```

---

# 20. Running the Complete Solver

The final solver is:

```text
solver/solve.py
```

Run:

```bash
python3 solver/solve.py
```

The solver automatically processes all five public polynomials.

The high-level execution is:

```text
H[0] → recover → verify → decrypt
H[1] → recover → verify → decrypt
H[2] → recover → verify → decrypt
H[3] → recover → verify → decrypt
H[4] → recover → verify → decrypt
                    │
                    ▼
              XOR plaintexts
                    │
                    ▼
                  FLAG
```

The final flag is also saved as:

```text
flag.txt
```

---

# 21. Experimental Solver: `ntru_attack.py`

During development, an initial lattice solver was used to test the attack against `H[0]`.

Run:

```bash
python3 solver/ntru_attack.py
```

This implementation performs:

```text
LLL
 ↓
BKZ-5
 ↓
BKZ-10
 ↓
BKZ-15
 ↓
BKZ-20
```

and searches the reduced basis for a pair of ternary weight-80 vectors.

A successful recovery is written to:

```text
key0.txt
```

---

# 22. Experimental Solver: `ntru_bkz.py`

A second implementation focuses on stronger BKZ reduction.

Run:

```bash
python3 solver/ntru_bkz.py 0
```

The argument selects the public polynomial.

All five can be tested independently:

```bash
python3 solver/ntru_bkz.py 0
python3 solver/ntru_bkz.py 1
python3 solver/ntru_bkz.py 2
python3 solver/ntru_bkz.py 3
python3 solver/ntru_bkz.py 4
```

The implementation progressively tries:

```text
BKZ-20
BKZ-30
BKZ-40
BKZ-50
BKZ-60
```

Recovered keys are saved as:

```text
key0.json
key1.json
key2.json
key3.json
key4.json
```

---

# 23. Useful Debugging Commands

Check the solver files:

```bash
find solver -maxdepth 1 -type f -print | sort
```

Check the challenge data:

```bash
find . -maxdepth 3 -type f -print | sort
```

Check Python dependencies:

```bash
python3 -m pip list | grep -i fpylll
```

Check the main solver syntax:

```bash
python3 -m py_compile solver/solve.py
```

Check the experimental solvers:

```bash
python3 -m py_compile solver/ntru_attack.py
python3 -m py_compile solver/ntru_bkz.py
```

If all files compile successfully, Python produces no error output.

---

# 24. Solver Architecture

The final `solve.py` can be divided into five logical components.

### Polynomial Arithmetic

```text
tr()
sb()
ml()
dv()
iv()
pm()
sh()
```

These reproduce the challenge's custom polynomial operations.

### Cryptographic Layer

```text
ky()
dc()
```

These reproduce:

```text
SHA3-256 key derivation
HMAC-SHA256 verification
SHAKE-256 keystream generation
```

### Lattice Layer

```text
center()
build_lattice()
```

These transform the public polynomial relation into a lattice problem.

### Key Recovery

```text
is_pm01()
extract_key()
recover()
verify_key()
```

These identify and validate the short secret vectors.

### Final Recovery

The main routine:

```text
recover all five keys
        ↓
decrypt all five messages
        ↓
XOR plaintexts
        ↓
write flag.txt
```

---

# 25. Complete Attack Summary

The vulnerability can be summarized mathematically.

The challenge publishes:

```text
h = b · a⁻¹ mod q
```

which gives:

```text
a · h = b mod q
```

The secrets satisfy:

```text
a_i, b_i ∈ {-1,0,+1}
```

and:

```text
weight(a) = weight(b) = 80
```

This means:

```text
(a,b)
```

is a very short vector satisfying a public modular equation.

We embed the equation into:

```text
      [ I   H ]
L  =  [       ]
      [ 0   qI ]
```

with dimension:

```text
256
```

and use:

```text
LLL → BKZ
```

to recover the short vector.

After recovery:

```text
(a,b)
   ↓
key derivation
   ↓
HMAC verification
   ↓
SHAKE-256 decryption
   ↓
five plaintexts
   ↓
XOR
   ↓
FLAG
```

---

# 26. Files

The challenge write-up is organized as:

```text
fence/
├── README.md
└── solver/
    ├── solve.py
    ├── ntru_attack.py
    └── ntru_bkz.py
```

### `solve.py`

Complete end-to-end solution.

### `ntru_attack.py`

Initial NTRU/lattice attack implementation.

### `ntru_bkz.py`

Stronger BKZ-based experimental implementation.

---

# 27. Flag

The final recovered flag is:

```text
ASIS{qu4ntum_c0h3r3nc3_1n_0v3r5tr3tch3d_h4rm0n1c_f13ld5!}
```

---

# 28. Conclusion

FENCE is primarily a lattice-recovery challenge rather than a direct attack against the underlying hash primitives.

The decisive weakness is the combination of:

```text
small ternary secret coefficients
+
fixed secret weight
+
public NTRU-style relation
```

This allows the secret polynomials to be represented as unusually short lattice vectors.

LLL and BKZ recover the secret structure, after which the rest of the challenge can be reproduced directly from the provided cryptographic implementation.

The final attack is therefore:

```text
NTRU relation
      ↓
Negacyclic matrix
      ↓
256-dimensional lattice
      ↓
LLL / BKZ
      ↓
Ternary secret recovery
      ↓
Algebraic verification
      ↓
SHA3-256 key derivation
      ↓
HMAC-SHA256 verification
      ↓
SHAKE-256 decryption
      ↓
Five plaintexts
      ↓
XOR
      ↓
ASIS{qu4ntum_c0h3r3nc3_1n_0v3r5tr3tch3d_h4rm0n1c_f13ld5!}
```

**Solved.**
