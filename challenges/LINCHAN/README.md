# LINCHAN

> **OLYMPICS CTF 2026 — Cryptography**

## Challenge Overview

**Challenge:** LINCHAN
**Category:** Cryptography
**Platform:** OLYMPICS CTF 2026
**Environment:** Kali Linux
**Flag:** `ASIS{Mr.__L1nChaN_h3aViEr__GFq2__ma7ch!nG_9aUntl3t!!?}`

### Challenge Download

[Download challenge archive](https://ctf.olympics.tech/tasks/linchan_06fa8bb304d3897d6f8a4aeab998c4826420da2e.txz?utm_source=chatgpt.com)

---

## TL;DR

LINCHAN is a custom cryptographic construction based on matrices over `GF(2)`.

The challenge generates several collections of `32 × 32` binary matrices. Some collections are related by conjugation with a secret invertible matrix:

```text
D = S C S⁻¹
```

The same secret matrices `S` are later used as input to a SHAKE256-based key derivation function. The resulting key protects the flag with ChaCha20-Poly1305.

The intended attack was approximately:

```text
output.txt
    │
    ├── Base85 decode
    │
    ├── zlib decompress
    │
    └── JSON
         │
         ├── 112 matrix boxes
         │
         ├── identify conjugate pairs
         │
         ├── recover S over GF(2)
         │
         ├── derive SHAKE256 key
         │
         └── decrypt ChaCha20-Poly1305
                    │
                    ▼
                  FLAG
```

The important weakness is that information about the hidden conjugation structure leaks through the published matrix collections, allowing the intended solver to identify matching conjugate instances and recover the secret matrices.

---

# 1. Files

The challenge archive contains the generator and its output.

Relevant files:

```text
linchan/
├── linchan.py
└── output.txt
```

Observed sizes:

```text
linchan.py    2935 bytes
output.txt    309924 bytes
```

`linchan.py` is the challenge generator.

`output.txt` is the encoded challenge output containing the matrix boxes and encrypted ciphertext.

---

# 2. Initial Reconnaissance

The following commands were used during the initial analysis.

```bash
sudo apt install -y python3 python3-pip gcc xz-utils
pip3 install --user cryptography
```

Create a working directory:

```bash
mkdir -p ~/ctf/linchan
cd ~/ctf/linchan
```

Download the challenge:

```bash
curl -fsSL -o linchan.txz \
"https://ctf.olympics.tech/tasks/linchan_06fa8bb304d3897d6f8a4aeab998c4826420da2e.txz"
```

Inspect the archive:

```bash
ls -la
file linchan.txz
tar -tf linchan.txz
```

Extract it:

```bash
tar -xf linchan.txz
ls -la
```

Inspect the challenge files:

```bash
file linchan.py output.txt
wc -c linchan.py output.txt
```

Inspect the generator:

```bash
head -80 linchan.py
tail -40 linchan.py
```

Search for cryptographic and challenge-related functionality:

```bash
rg -n "flag|shake|ChaCha|_n|_l|_d|_z|_k|_e|_b|_m|_i" linchan.py
```

---

# 3. Understanding `output.txt`

`output.txt` is not directly readable JSON.

It is encoded as:

```text
Base85
   ↓
zlib compressed data
   ↓
JSON
```

The decoding process is:

```python
import base64
import zlib
import json
from pathlib import Path

t = Path("output.txt").read_text().strip()

blob = base64.b85decode(t)
raw = zlib.decompress(blob)
data = json.loads(raw)
```

The real challenge output produced:

```text
chars       309924
b85 decoded 247939
zlib        306247
```

The resulting JSON contains:

```text
v
n
ct
boxes
```

with:

```text
v = 2
n = 32
boxes = 112
```

The ciphertext field contains 103 Base85 characters.

---

# 4. Inspecting the JSON Structure

Each element in `boxes` has the following general structure:

```json
{
    "m": 16,
    "x": "..."
}
```

The value of `m` determines the matrix collection size.

The observed distribution was:

```text
m = 16 → 38 boxes
m = 17 → 38 boxes
m = 18 → 36 boxes
```

Total:

```text
38 + 38 + 36 = 112
```

This matches the generator exactly.

---

# 5. Reading the Generator

Several constants in `linchan.py` are important:

```python
_n = 32
_l = ((16, 2), (17, 2), (18, 1))
_d = 34
_z = b"linchan/v2"
```

Therefore, the challenge operates on `32 × 32` binary matrices.

The generator creates:

```text
m = 16 → 2 secret conjugate pairs + 34 decoys
m = 17 → 2 secret conjugate pairs + 34 decoys
m = 18 → 1 secret conjugate pair + 34 decoys
```

For example, for `m = 16`:

```text
2 × (C,D) + 34 decoys
= 4 + 34
= 38 boxes
```

Likewise:

```text
m = 17:
2 × (C,D) + 34
= 38
```

and:

```text
m = 18:
1 × (C,D) + 34
= 36
```

This explains all 112 published boxes.

---

# 6. Matrix Representation

A matrix is represented as a list of 32 integers.

Each integer represents a 32-bit row.

Therefore:

```text
32 rows × 32 bits
```

represents a `32 × 32` matrix over:

```text
GF(2)
```

The generator implements its own matrix operations.

Important functions include:

```python
_r(A)
```

Computes the rank of a matrix over `GF(2)`.

```python
_m(A, B)
```

Performs matrix multiplication.

```python
_t(A)
```

Computes the transpose.

```python
_i(A)
```

Computes the inverse.

```python
_g()
```

Generates a random invertible `32 × 32` matrix.

---

# 7. Secret Conjugation

The core cryptographic construction is found here:

```python
C, S = _b(m, True)
T = _i(S)
D = [_m(_m(S, A), T) for A in C]
```

Mathematically:

```text
D = S C S⁻¹
```

where:

* `C` is the original matrix collection.
* `S` is a secret invertible matrix.
* `D` is the conjugated collection.
* `S⁻¹` is the inverse of `S`.

Therefore:

```text
D = S C S⁻¹
```

Multiplying both sides by `S` gives:

```text
D S = S C
```

This is the key equation used during the intended recovery of `S`.

---

# 8. Why Conjugation Matters

Two matrices related by:

```text
D = S C S⁻¹
```

belong to the same conjugacy class.

The challenge publishes both types of objects without directly publishing `S`.

It also mixes them with decoy matrix collections.

Therefore, the attack has two major stages:

```text
1. Determine which published boxes form conjugate pairs.
2. Recover the conjugating matrix S.
```

Once `S` is recovered, it can be used to reconstruct the encryption key.

---

# 9. Additional Obfuscation

The generator does not publish the matrices directly.

The `_o()` function applies another transformation:

```python
def _o(B):
    B = [_c(x, B) for x in _u(len(B))]
    return [_t(A) for A in B] if secrets.randbits(1) else B
```

This performs a random change of basis on the matrix list and may also transpose individual matrices.

Consequently, the attacker cannot simply compare the matrices byte-for-byte.

The attack therefore requires an invariant or fingerprint that survives the transformations.

---

# 10. The Intended Pairing Attack

According to the original solving notes, the intended solver used a rank-based fingerprint.

The idea was to construct a rank histogram involving:

```text
rank(A XOR X)
```

for a collection of test matrices `X`.

The resulting histogram was used as a fingerprint for identifying matrix collections that belonged to the same conjugacy class.

Conceptually:

```text
Box A
   │
   ├── rank-based fingerprint
   │
   ▼
Histogram H

Box B
   │
   ├── rank-based fingerprint
   │
   ▼
Histogram H
```

Matching fingerprints indicate a candidate pair:

```text
(C, D)
```

with:

```text
D = S C S⁻¹
```

---

# 11. Recovering S

Once a candidate pair `(C,D)` is identified, the conjugation equation is:

```text
D = S C S⁻¹
```

which can be rewritten as:

```text
D S = S C
```

This is a system of linear equations over `GF(2)`.

The solver can therefore construct a linear system whose unknowns are the bits of `S`.

A valid solution must additionally satisfy:

```text
rank(S) = 32
```

because `S` must be invertible.

The original notes reported that a unique invertible `S` was recovered for each required pair.

---

# 12. Key Derivation

The recovered secret matrices are not used directly as the ChaCha20 key.

The generator canonicalizes every `S` using:

```python
def _f(S):
    T = _i(S)
    return min(
        _p(S),
        _p(T),
        _p(_t(S)),
        _p(_t(T))
    )
```

where `_p()` serializes the matrix:

```python
def _p(A):
    return b"".join(
        x.to_bytes(4, "little")
        for x in A
    )
```

The canonical representation therefore considers:

```text
S
S⁻¹
Sᵀ
(S⁻¹)ᵀ
```

and selects the lexicographically smallest serialized representation.

---

# 13. SHAKE256 Key Derivation

The final key material is produced by:

```python
def _k(S):
    X = b"".join(sorted(_f(A) for A in S))
    return hashlib.shake_256(
        b"linchan-v2/key\0" + X
    ).digest(32)
```

Therefore:

```text
K =
SHAKE256(
    b"linchan-v2/key\0"
    ||
    sorted(canonical(S₁), canonical(S₂), ...)
)
```

with an output length of:

```text
32 bytes
```

This gives the 256-bit key required by ChaCha20-Poly1305.

---

# 14. ChaCha20-Poly1305

The challenge encrypts the flag using:

```python
nonce = secrets.token_bytes(12)

ct = nonce + ChaCha20Poly1305(
    _k(K)
).encrypt(
    nonce,
    msg,
    _z
)
```

The associated data is:

```python
_z = b"linchan/v2"
```

The encrypted result contains:

```text
12-byte nonce
+
ChaCha20-Poly1305 ciphertext + authentication tag
```

The entire value is then Base85 encoded.

---

# 15. Complete Intended Solve Chain

The complete attack can be summarized as:

```text
                 output.txt
                     │
                     ▼
              Base85 decoding
                     │
                     ▼
                zlib inflate
                     │
                     ▼
                  JSON
                     │
                     ▼
               112 boxes
                     │
                     ▼
        analyze matrix collections
                     │
                     ▼
       rank-based conjugacy fingerprint
                     │
                     ▼
             identify C / D pairs
                     │
                     ▼
             D = S C S⁻¹
                     │
                     ▼
                D S = S C
                     │
                     ▼
         solve linear system over GF(2)
                     │
                     ▼
              recover invertible S
                     │
                     ▼
           canonicalize each S
                     │
                     ▼
               sort encodings
                     │
                     ▼
                 SHAKE256
                     │
                     ▼
             256-bit encryption key
                     │
                     ▼
          ChaCha20-Poly1305 decrypt
                     │
                     ▼
                    FLAG
```

---

# 16. Reproduction Status

There is an important limitation with the surviving artifacts.

The original contest solver is no longer available.

The original notes reference:

```text
solve_linchan.py
```

but the file was not present in the recovered artifacts.

The following files were also unavailable:

```text
rank32.c
recovered_S.json
solver stdout
original SHAKE input
```

Later attempts reconstructed parts of the solver from the generator and surviving notes:

```text
solve_linchan.py
rank32.c
recovered_S.json
solver_output.txt
```

However, these were reconstructions rather than the original contest artifacts.

---

# 17. Failed Reconstruction

The reconstructed solver successfully reproduced the initial parsing stage:

```text
boxes = 112
version = 2
matrix size = 32
```

However, the reconstructed rank-histogram stage produced:

```text
group size histogram {1: 112}
recovered S count 0
```

No secret matrices were recovered.

The reason is significant.

If `X` is sampled as a uniformly random `32 × 32` binary matrix, then:

```text
A XOR X
```

is itself uniformly distributed regardless of `A`.

Therefore:

```text
rank(A XOR X)
```

does not provide a useful conjugacy fingerprint under that sampling strategy.

This means the original solver must have used a specific rank-histogram construction that is no longer available in the recovered artifacts.

The missing information includes parameters such as:

```text
- how X was generated
- how many samples were used
- whether X was shared between matrices
- how histograms were normalized
- whether the fingerprint was calculated per matrix or per box
```

Consequently, the original pairing stage cannot currently be reproduced exactly.

---

# 18. Evidence and Provenance

The flag itself was recovered and remains available in:

```text
linchan_flag.txt
```

The surviving notes recorded:

```text
about 112 boxes
conjugate pairs matched by rank histograms
unique invertible S recovered
FLAG ASIS{Mr.__L1nChaN_h3aViEr__GFq2__ma7ch!nG_9aUntl3t!!?}
```

The intermediate secret matrices were not preserved.

Therefore, this write-up distinguishes between:

```text
Verified from surviving challenge files
```

and:

```text
Recovered from original solving notes
```

rather than presenting reconstructed code as if it were the original contest solver.

---

# 19. Original Generator

The following is the surviving `linchan.py` generator used to analyze the challenge:

```python
#!/usr/bin/env python3

import base64
import hashlib
import json
import secrets
import zlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from flag import flag


_n = 32
_l = ((16, 2), (17, 2), (18, 1))
_d = 34
_z = b"linchan/v2"

def _r(A):
    P = {}
    for x in A:
        while x:
            i = x.bit_length() - 1
            if i in P:
                x ^= P[i]
            else:
                P[i] = x
                break
    return len(P)

def _v(A):
    return sum(x << (_n * i) for i, x in enumerate(A))

def _a(A, B):
    return [x ^ y for x, y in zip(A, B)]

def _m(A, B):
    R = []
    for x in A:
        y = 0
        while x:
            b = x & -x
            y ^= B[b.bit_length() - 1]
            x ^= b
        R.append(y)
    return R

def _t(A):
    R = [0] * _n
    for i, x in enumerate(A):
        while x:
            b = x & -x
            R[b.bit_length() - 1] |= 1 << i
            x ^= b
    return R

def _i(A):
    R = [x | (1 << (_n + i)) for i, x in enumerate(A)]
    for i in range(_n):
        j = next((j for j in range(i, _n) if (R[j] >> i) & 1), None)
        if j is None:
            raise ValueError
        R[i], R[j] = R[j], R[i]
        for j in range(_n):
            if j != i and ((R[j] >> i) & 1):
                R[j] ^= R[i]
    return [x >> _n for x in R]

def _g():
    while True:
        A = [secrets.randbits(_n) for _ in range(_n)]
        if _r(A) == _n:
            return A

def _h():
    while True:
        A = [secrets.randbits(25) for _ in range(_n)]
        B = [secrets.randbits(_n) for _ in range(25)]
        X = _m(A, B)
        if _r(X) == 25:
            return X

def _c(x, B):
    R = [0] * _n
    while x:
        b = x & -x
        R = _a(R, B[b.bit_length() - 1])
        x ^= b
    return R

def _u(m):
    B = []
    while len(B) < m:
        x = secrets.randbits(m)
        if _r(B + [x]) == len(B) + 1:
            B.append(x)
    return B

def _b(m, q=False):
    B = [_h(), _h()] if q else []
    while len(B) < m:
        X = [secrets.randbits(_n) for _ in range(_n)]
        if _r([_v(A) for A in B] + [_v(X)]) == len(B) + 1:
            B.append(X)
    return B

def _o(B):
    B = [_c(x, B) for x in _u(len(B))]
    return [_t(A) for A in B] if secrets.randbits(1) else B

def _p(A):
    return b"".join(x.to_bytes(4, "little") for x in A)

def _f(S):
    T = _i(S)
    return min(_p(S), _p(T), _p(_t(S)), _p(_t(T)))

def _k(S):
    X = b"".join(sorted(_f(A) for A in S))
    return hashlib.shake_256(
        b"linchan-v2/key\0" + X
    ).digest(32)

def _e(B):
    return base64.b85encode(b"".join(_p(A) for A in B)).decode()

def main():
    B, K = [], []

    for m, c in _l:
        for _ in range(c):
            C, S = _b(m, True), _g()
            T = _i(S)
            D = [_m(_m(S, A), T) for A in C]

            B += [(m, _o(C)), (m, _o(D))]
            K.append(S)

        for _ in range(_d):
            B.append((m, _o(_b(m))))

    secrets.SystemRandom().shuffle(B)

    msg = flag if isinstance(flag, bytes) else str(flag).encode()

    nonce = secrets.token_bytes(12)

    ct = nonce + ChaCha20Poly1305(
        _k(K)
    ).encrypt(
        nonce,
        msg,
        _z
    )

    X = {
        "v": 2,
        "n": _n,
        "ct": base64.b85encode(ct).decode(),
        "boxes": [
            {"m": m, "x": _e(C)}
            for m, C in B
        ],
    }

    raw = json.dumps(
        X,
        separators=(",", ":")
    ).encode()

    open("output.txt", "wb").write(
        base64.b85encode(
            zlib.compress(raw, 9)
        )
    )


if __name__ == "__main__":
    main()
```

---

# 20. Key Takeaways

The important cryptographic concepts in this challenge are:

### Matrices over GF(2)

The challenge represents binary matrices using 32-bit integers and performs arithmetic over:

```text
GF(2)
```

where addition corresponds to XOR.

### Conjugation

The secret relationship is:

```text
D = S C S⁻¹
```

which can be rearranged into the linear equation:

```text
D S = S C
```

### Secret Recovery

Once matching conjugate pairs are identified, the unknown `S` can be recovered as a solution to a linear system over `GF(2)`, subject to the requirement that `S` is invertible.

### KDF

The recovered matrices are canonicalized and passed through:

```text
SHAKE256
```

to produce a 32-byte key.

### AEAD

The flag is protected using:

```text
ChaCha20-Poly1305
```

with:

```text
AAD = b"linchan/v2"
```

The AEAD itself is not the fundamental weakness. The vulnerability is the leakage of structural information that enables recovery of the secret matrices used by the KDF.

---

# 21. Final Flag

```text
ASIS{Mr.__L1nChaN_h3aViEr__GFq2__ma7ch!nG_9aUntl3t!!?}
```

---

## Reproducibility Note

This write-up documents the challenge implementation, the surviving analysis, the intended cryptanalytic path, and the recovered flag.

The original contest solver and the intermediate `S` matrices are unavailable. Therefore, the exact pairing and key-recovery stage is **not currently a fully reproducible attachment-to-flag exploit**.

This distinction is intentional: reconstructed artifacts are not presented as the original solver.
