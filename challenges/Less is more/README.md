# Less is more — OLYMPICS CTF 2026

**Category:** Cryptography / Cryptographic Protocol
**Status:** Solved
**Flag:** `ASIS{iZ_1tEr4t10n_5k1p_m4ke5_n0_1nn0c3nT_r3sPonse!!!?}`

> **Note:** The original contest solver and recovered key material are no longer available. This write-up documents the original analysis, the vulnerability, the solve chain, and the recovered flag. It does **not** claim to provide a fully reproducible exploit.

---

## Challenge

**Challenge name:** Less is more

**Download:**

`https://ctf.olympics.tech/tasks/new_less_is_more_ea1eac39bcc48aec35b0e24fedd620acacca68a9.txz`

The challenge implements a custom signing/commitment device using:

* finite-field linear algebra over `F_827`
* Cauchy matrices
* secret column permutations
* secret scaling vectors
* Merkle trees
* challenge/response transcripts
* an iterative state mechanism
* SHAKE256
* XOR-based vault encryption

The final flag is encrypted inside `flag.enc`.

The intended cryptographic construction is reasonably complicated, but the implementation contains an information leak in the iteration/skip mechanism.

---

# 1. Initial Inspection

The challenge archive was downloaded and extracted on Kali Linux.

```bash
sudo apt install -y python3 python3-pip xz-utils
pip3 install --user numpy

mkdir -p ~/ctf/less
cd ~/ctf/less

curl -fsSL -o less.txz \
"https://ctf.olympics.tech/tasks/new_less_is_more_ea1eac39bcc48aec35b0e24fedd620acacca68a9.txz"

ls -la
file less.txz
tar -tf less.txz
tar -xf less.txz

find . -type f -exec ls -la {} \;
```

The extracted challenge contains:

```text
new_less_is_more/
├── challenge.py
└── flag.enc
```

Inspect the files:

```bash
file new_less_is_more/challenge.py new_less_is_more/flag.enc

wc -c \
    new_less_is_more/challenge.py \
    new_less_is_more/flag.enc
```

Recorded sizes:

```text
challenge.py    5691 bytes
flag.enc        75619047 bytes
```

The source was then inspected:

```bash
head -80 new_less_is_more/challenge.py

rg -n \
"REAL|SLOTS|DECOY|MAGIC|cover|Merkle|vault|shake|flag|pack_key" \
new_less_is_more/challenge.py
```

---

# 2. `flag.enc` Structure

The encrypted file starts with a custom magic value.

```bash
python3 - <<'PY'
p = open("new_less_is_more/flag.enc", "rb").read(32)

print(p)
print(p[:8])
PY
```

The header is:

```text
41 53 49 53 31 31 37 04
```

which corresponds to:

```text
ASIS117\x04
```

The complete file format is:

```text
MAGIC (8 bytes)
    ||
    \/ 
uint32 big-endian body length
    ||
    \/
zlib-compressed pickle
```

The body contains approximately 75 MB of serialized challenge data.

The relevant structure is:

```python
{
    "pub": {...},
    "records": [...],
    "sealed": bytes
}
```

The recorded header information was:

```text
magic  = ASIS117\x04
body   = 75619035 bytes
total  = 75619047 bytes
```

---

# 3. Challenge Parameters

The main parameters are defined directly in `challenge.py`:

```python
P, N, K, T, W = 827, 548, 274, 345, 75

REAL, SLOTS, DECOY = 7, 17, 15

MAGIC = b'ASIS117\x04'
```

Therefore:

| Parameter          | Value |
| ------------------ | ----: |
| Field modulus      | `827` |
| Matrix width       | `548` |
| Base rows          | `274` |
| Merkle leaves      | `345` |
| Challenge weight   |  `75` |
| Real keys          |   `7` |
| Total public slots |  `17` |
| Fake Merkle leaves |  `15` |

The cryptographic operations are performed over the finite field:

```text
F_827
```

---

# 4. Base Matrix

The device constructs a Cauchy-style base matrix.

For each row/column pair:

```text
g[i][j] = 1 / (x_i - y_j) mod P
```

where:

```text
x_i ∈ [0, K)
y_j ∈ [K, K + N)
```

The resulting matrix is then row-reduced.

The implementation is:

```python
def base():
    return red([
        [
            inv((x - y) % P)
            for y in range(K, K + N)
        ]
        for x in range(K)
    ])
```

The reduction routine performs Gaussian elimination over `F_827`.

---

# 5. Secret Key Construction

Each secret key consists of two components:

```text
(p, d)
```

where:

* `p` is a permutation of `N = 548` elements.
* `d` is a vector of 548 non-zero field elements.

The key generation routine is:

```python
def keys(seed, count):
    out = []

    for i in range(count):
        z = hashlib.sha512(
            seed + i.to_bytes(2, 'big')
        ).digest()

        p = take(z, b'p', N, N)

        d = [
            int.from_bytes(
                hashlib.sha256(
                    z + j.to_bytes(2, 'big')
                ).digest()[:4],
                'big'
            ) % (P - 1) + 1
            for j in range(N)
        ]

        out.append((p, d))

    return out
```

There are:

```text
7 real keys
```

and:

```text
10 additional junk keys
```

for a total of:

```text
17 public slots
```

---

# 6. Public Key Construction

The public representation of a key is generated from the base matrix.

```python
def public(g, item):
    p, d = item

    return red([
        [
            (g[i][p[j]] * inv(d[j])) % P
            for j in range(N)
        ]
        for i in range(K)
    ])
```

The resulting public matrices are shuffled:

```python
self.pub = [public(self.g, x) for x in self.key + junk]
random.shuffle(self.pub)
```

Therefore, the attacker sees the public matrices but not the corresponding secret permutations and scale vectors.

---

# 7. Merkle Tree

Each transcript creates a fresh Merkle tree.

The root is generated from:

```python
root = hashlib.sha256(
    b'r' + self.master + salt + msg
).digest()
```

The tree expands using domain-separated hashes:

```python
a[2 * i] = hashlib.sha256(
    b'l' + a[i]
).digest()

a[2 * i + 1] = hashlib.sha256(
    b'r' + a[i]
).digest()
```

The tree depth is selected so that it contains at least:

```text
T = 345
```

leaves.

---

# 8. The `cover()` Function

The important part of the challenge is the Merkle covering algorithm.

```python
def cover(a, depth, f):
    ans = []

    def go(u, lo, hi):
        if lo >= T:
            return

        end = min(hi, T)

        if all(f[i] == 0 for i in range(lo, end)):
            ans.append([u, a[u]])
            return

        if hi - lo == 1:
            return

        md = (lo + hi) >> 1

        go(u << 1, lo, md)
        go((u << 1) | 1, md, hi)

    go(1, 0, 1 << depth)

    return ans
```

Conceptually:

```text
f[i] = 0
```

means that a complete subtree can be represented by a single Merkle node.

If any element in the subtree is active:

```text
f[i] = 1
```

the algorithm descends into that subtree.

This is where the implementation mistake becomes important.

---

# 9. Challenge Generation

The challenge vector is generated from the commitment:

```python
b = chal(cmt, salt, msg)
```

The vector has length:

```text
T = 345
```

and contains exactly:

```text
W = 75
```

challenged positions.

Each selected position receives a value in:

```text
1 .. REAL
```

Therefore the value identifies one of the seven real key classes.

Initially the visibility vector is:

```python
f = [int(x != 0) for x in b]
```

So normally:

```text
b[i] != 0  →  f[i] = 1
b[i] == 0  →  f[i] = 0
```

---

# 10. The Critical Vulnerability

The vulnerable code is:

```python
target = (37 * serial + 11) % T

if int.from_bytes(
    hashlib.sha256(b'v' + root).digest()[:2],
    'big'
) % 100 < 72:

    f[target] = self.state[target]

self.state = f
```

Instead of preserving the current challenge state, the implementation replaces one position with the **previous transcript's state**.

The intended behavior should effectively have been independent of the previous `self.state`.

Instead:

```text
current challenge
       │
       ▼
     f[i]
       │
       │ overwrite
       ▼
previous self.state[target]
```

This creates a cross-transcript dependency.

That dependency is the central bug.

---

# 11. Recovering the Leak

Immediately after the state modification, the program calculates:

```python
hit = [
    i
    for i in range(T)
    if b[i] and not f[i]
]
```

This is extremely important.

A hit means:

```text
b[i] != 0
```

but:

```text
f[i] == 0
```

Therefore the challenge requested information about a leaf which was nevertheless treated as hidden.

These positions are precisely the places where the skip mechanism creates anomalous behavior.

The implementation later removes `_hit` from the stored record:

```python
for i in q.pop('_hit'):
    got[b[i] - 1] += 1
```

The value:

```python
b[i] - 1
```

identifies one of the seven real key classes.

---

# 12. Why the Merkle Cover Leaks Information

The Merkle path is generated using the corrupted vector:

```python
path = [
    [token(cmt, u), seed]
    for u, seed in cover(tr, depth, f)
]
```

Because `cover()` only exposes complete subtrees for positions where:

```text
f[i] == 0
```

changing a single `f[target]` changes the shape of the published Merkle cover.

This means the attacker can compare transcript behavior against the expected challenge structure.

The resulting leakage allows hidden positions associated with the real keys to be identified.

Conceptually:

```text
Normal challenge
      │
      ▼
 challenge vector b
      │
      ▼
 visibility f
      │
      ▼
 Merkle cover
```

becomes:

```text
challenge vector b
      │
      ▼
 visibility f
      │
      │
      └── previous state injected
                  │
                  ▼
             corrupted f
                  │
                  ▼
             Merkle cover
                  │
                  ▼
              information leak
```

The challenge title is therefore appropriate:

> **Less is more**

Less coverage means more information leaks through the structure of the transcript.

---

# 13. Response Construction

For every challenged position, the device creates a response:

```python
for i, x in enumerate(b):
    if x:
        v = take(leaf[i], b'n', N, K)

        rsp.append([
            label(cmt, leaf[i]),
            bits([
                invs[x - 1][j]
                for j in v
            ])
        ])
```

The important observation is that the response depends on:

```text
x - 1
```

which selects one of the seven real secret permutations.

Thus the transcripts contain information tied to the secret key classes.

There is also an additional 14% probability of replacing one response entry with junk:

```python
if int.from_bytes(
    hashlib.sha256(b'w' + root).digest()[:2],
    'big'
) % 100 < 14:

    j = int.from_bytes(
        hashlib.sha256(b'x' + root).digest()[:2],
        'big'
    ) % len(rsp)

    rsp[j][1] = bits(
        take(root, b'z', N, K)
    )
```

This acts as another source of noise that must be distinguished from genuine responses.

---

# 14. Transcript Generation

The device keeps generating transcripts until each of the seven classes has accumulated at least 90 leaked hits:

```python
while min(got) < 90:
    q = box.one(
        ('m%05d' % serial).encode(),
        serial
    )

    b = chal(
        q['cmt'],
        q['salt'],
        q['msg']
    )

    for i in q.pop('_hit'):
        got[b[i] - 1] += 1

    records.append(q)
    serial += 1
```

Therefore the final capture contains a large number of transcripts.

The records are shuffled before being written:

```python
random.shuffle(records)
```

---

# 15. Vault Encryption

After all seven classes have been sufficiently observed, the actual flag is encrypted.

The key material is serialized by:

```python
def pack_key(key):
    out = bytearray()

    for p, d in key:
        u = inv(d[0])

        for x in p:
            out.extend(
                x.to_bytes(2, 'little')
            )

        for x in d:
            out.extend(
                (x * u % P).to_bytes(2, 'little')
            )

    return bytes(out)
```

The vault pad is then:

```python
pad = hashlib.shake_256(
    b'o' + pack_key(box.key)
).digest(len(flag))
```

Finally:

```python
sealed = bytes(
    x ^ y
    for x, y in zip(flag, pad)
)
```

So recovering the seven real keys is sufficient to derive the pad and recover the flag.

---

# 16. Complete Solve Chain

The original analysis followed this conceptual chain:

```text
flag.enc
   │
   ▼
Parse custom header
   │
   ▼
zlib + pickle
   │
   ▼
Extract public parameters and transcripts
   │
   ▼
Analyze challenge.py
   │
   ▼
Understand Merkle cover()
   │
   ▼
Identify iteration-state overwrite
   │
   ▼
Detect skip-induced transcript anomalies
   │
   ▼
Recover leaked key classes
   │
   ▼
Recover 7 real permutations
   │
   ▼
Recover 7 scale vectors
   │
   ▼
Reconstruct pack_key()
   │
   ▼
SHAKE256(b'o' + pack_key)
   │
   ▼
XOR with sealed
   │
   ▼
FLAG
```

---

# 17. Reproduction Status

The original contest solver is **not available**.

The notes referenced:

```text
solve_less.py
```

but the file was not preserved.

The following artifacts are also missing:

```text
solve_less.py
recovered permutations
recovered scale vectors
vault key / SHAKE input
solver stdout
```

Therefore this repository should **not** claim that the write-up contains a fully executable exploit.

The currently preserved evidence consists of:

```text
challenge.py
flag.enc
less_flag.txt
```

The stored flag is:

```text
ASIS{iZ_1tEr4t10n_5k1p_m4ke5_n0_1nn0c3nT_r3sPonse!!!?}
```

---

# 18. Useful Commands

Inspect the challenge:

```bash
find . -type f -exec ls -lh {} \;
```

Inspect the source:

```bash
less new_less_is_more/challenge.py
```

Search security-critical functions:

```bash
rg -n \
"keys|public|tree|cover|chal|one|pack_key|shake|sealed" \
new_less_is_more/challenge.py
```

Inspect the encrypted file:

```bash
file new_less_is_more/flag.enc

ls -lh new_less_is_more/flag.enc

xxd -l 64 new_less_is_more/flag.enc
```

Verify the magic:

```bash
python3 - <<'PY'
from pathlib import Path

p = Path("new_less_is_more/flag.enc").read_bytes()

print("magic:", p[:8])
print("body length:", int.from_bytes(p[8:12], "big"))
print("actual body:", len(p) - 12)
PY
```

Inspect the first bytes:

```bash
python3 - <<'PY'
from pathlib import Path

p = Path("new_less_is_more/flag.enc").read_bytes()

print(p[:32])
print(p[:8] == b"ASIS117\x04")
PY
```

---

# 19. Important Implementation Details

The most important functions for understanding the vulnerability are:

```text
Box.one()
cover()
chal()
pack_key()
```

In particular:

```python
f = [int(x != 0) for x in b]
```

followed by:

```python
f[target] = self.state[target]
```

and then:

```python
hit = [
    i
    for i in range(T)
    if b[i] and not f[i]
]
```

creates the critical state-dependent behavior.

The resulting `f` is then passed directly into:

```python
cover(tr, depth, f)
```

which changes the public Merkle representation.

That is the central cryptographic flaw exploited by the solution.

---

# 20. Lessons Learned

This challenge demonstrates how a seemingly small state-management mistake can invalidate a much larger cryptographic construction.

The underlying components individually look strong:

* large finite-field matrices
* secret permutations
* secret scaling vectors
* Merkle commitments
* SHAKE256
* XOR-based encryption

However, the security of the complete system depends on how these components interact.

The critical mistake was reusing:

```python
self.state[target]
```

when constructing the current transcript's visibility vector.

That introduced state across supposedly independent transcripts.

The consequence was not a direct cryptographic break of SHAKE256 or the finite-field construction. Instead, the implementation leaked information through the **structure of the Merkle cover**.

The general lesson is:

> Cryptographic security can fail through protocol state and metadata leakage even when the underlying primitives themselves are secure.

---

# 21. Final Result

**Challenge:** Less is more
**Category:** Cryptography
**Status:** Solved

Flag:

```text
ASIS{iZ_1tEr4t10n_5k1p_m4ke5_n0_1nn0c3nT_r3sPonse!!!?}
```

---

## Files

Recommended directory structure:

```text
less-is-more/
├── README.md
├── challenge.py
└── flag.enc
```

The original solver was not preserved, so no runnable `solve_less.py` is included.
