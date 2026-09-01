# PANCAKE

> **OLYMPICS CTF 2026 — Cryptography Write-up**

## Overview

**Challenge:** PANCAKE
**Category:** Cryptography
**Status:** Solved

PANCAKE is a multi-stage cryptographic challenge involving:

* Recovery of a hidden 32-bit seed
* SHA-256 based key derivation
* AES-ECB
* Truncated AES output
* A 32-bit collision search
* AES-GCM authenticated decryption
* Known-plaintext analysis
* XOR keystream recovery

The challenge does not require breaking AES or SHA-256 directly. Instead, several weaknesses in the cryptographic construction can be chained together to recover the final flag.

---

## Challenge Files

The challenge provides a JSON file containing the encrypted challenge parameters:

```text
Pancake/
└── challenge.json
```

The important fields are:

```text
a      → SHA-256 seed hint
n[0]   → first nonce
n[1]   → second nonce
z.c    → AES-GCM ciphertext
z.t    → AES-GCM authentication tag
y.c    → final flag ciphertext
```

---

# 1. Recovering the Hidden Seed

The first weakness is the size of the secret seed.

The challenge derives a public hint using:

```python
hint = sha256(
    b"K1-SEED-HINT" + seed.to_bytes(4, "big")
).hexdigest()
```

The seed is only 32 bits:

```text
2^32 possible values
```

Therefore, instead of attempting to reverse SHA-256, we can perform an exhaustive search.

For every candidate:

```text
SHA256("K1-SEED-HINT" || seed)
```

is calculated and compared with the supplied value:

```text
challenge.json → a
```

The recovered seed is:

```text
0x22c4d3ef
```

---

# 2. Optimized Seed Brute Force

A native C implementation was used because performing billions of SHA-256 operations in Python would be unnecessarily slow.

The solver is:

```text
solver/brute_seed.c
```

The search is distributed across multiple CPU threads.

The relevant logic is:

```c
for (uint64_t s = start;
     s <= 0xFFFFFFFFULL && !found_flag;
     s += step) {

    buf[12] = (s >> 24) & 0xff;
    buf[13] = (s >> 16) & 0xff;
    buf[14] = (s >> 8) & 0xff;
    buf[15] = s & 0xff;

    SHA256(buf, 16, out);

    if (memcmp(out, target, 32) == 0) {
        found_seed = (uint32_t)s;
        found_flag = 1;
        return NULL;
    }
}
```

Compile:

```bash
gcc -O3 -pthread brute_seed.c -o brute_seed \
    $(pkg-config --cflags --libs openssl)
```

Run:

```bash
./brute_seed <HASH> 8
```

Or directly using `jq`:

```bash
./brute_seed "$(jq -r '.a' challenge.json)" 8
```

The recovered value is:

```text
22c4d3ef
```

Therefore:

```text
seed = 0x22c4d3ef
```

---

# 3. Deriving K1

The first cryptographic key is derived from the recovered seed:

```python
k1 = sha256(
    b"K1-SEED" + seed.to_bytes(4, "big")
).digest()
```

Thus:

```text
K1 = SHA256("K1-SEED" || seed)
```

The solver reproduces this derivation directly.

---

# 4. The AES-ECB Truncation

The next weakness is the use of a truncated AES output.

The challenge defines:

```python
DROP = 32
NONCE_BITS = 128 - DROP
```

Therefore:

```text
AES block size = 128 bits
discarded      = 32 bits
kept           = 96 bits
```

The solver extracts the upper 96 bits:

```python
def extract_upper(x: bytes) -> int:
    return int.from_bytes(x, "big") >> DROP
```

Instead of requiring the entire AES-128-bit output to match, only 96 bits are compared.

The remaining 32 bits are ignored.

This creates a practical collision search over a 32-bit space.

---

# 5. Constructing the AES Target

The challenge provides:

```python
n1 = int(ch["n"][0], 16)
n2 = int(ch["n"][1], 16)
```

AES-ECB is initialized using the recovered key:

```python
e = AES.new(k1, AES.MODE_ECB)
```

The target is generated from `n2`:

```python
target = extract_upper(
    e.encrypt(format_block(n2, 0))
)
```

where:

```python
def format_block(x: int, sep: int = 0) -> bytes:
    return (
        ((x & NONCE_MASK) << DROP) |
        (sep & DROP_MASK)
    ).to_bytes(16, "big")
```

The objective is to find another value:

```text
alt != n2
```

such that:

```text
upper96(AES(format_block(alt, 0)))
=
upper96(AES(format_block(n2, 0)))
```

---

# 6. Searching for the Collision

Because 32 bits of the AES output are discarded, the expected search complexity is approximately:

```text
2^32
```

This is again practical with an optimized native implementation.

The collision solver is:

```text
solver/search.c
```

The search space is:

```c
uint64_t total = 1ULL << drop;
```

Since:

```text
drop = 32
```

we obtain:

```text
total = 2^32
```

The implementation uses eight worker threads:

```c
int num_threads = 8;
```

Each thread receives a separate section of the search space.

The candidate is accepted when the discarded 32 bits are zero:

```c
if (out_block[12] == 0 &&
    out_block[13] == 0 &&
    out_block[14] == 0 &&
    out_block[15] == 0) {

    *w->found_flag = 1;
    memcpy(w->result_pt, out_block, 16);
    return NULL;
}
```

Compile:

```bash
gcc -O3 -pthread search.c -o search \
    $(pkg-config --cflags --libs openssl)
```

The Python solver invokes the binary automatically.

---

# 7. Verifying the Collision

After obtaining the alternative value:

```python
alt
```

the solver verifies that the truncated AES outputs are identical:

```python
j_n2 = extract_upper(
    e.encrypt(format_block(n2, 0))
)

j_alt = extract_upper(
    e.encrypt(format_block(alt, 0))
)

print("j equal", j_n2 == j_alt, hex(j_n2))
```

The important condition is:

```text
j_n2 == j_alt
```

while simultaneously:

```text
alt != n2
```

This proves that the truncated AES construction has been successfully collided.

---

# 8. Deriving the Sealed Ticket Key

The recovered values are then used to derive the AES-GCM key:

```python
key = sha256(
    b"SEALED-TICKET-KEY"
    + k1
    + n1.to_bytes(bw, "big")
    + alt.to_bytes(bw, "big")
).digest()[:16]
```

Because only 96 bits of the nonce are used:

```python
bw = (NONCE_BITS + 7) // 8
```

which gives:

```text
bw = 12
```

Therefore:

```text
KEY =
SHA256(
    "SEALED-TICKET-KEY"
    || K1
    || n1
    || alt
)[0:16]
```

---

# 9. Deriving the AES-GCM IV

The AES-GCM nonce is derived from the newly generated key:

```python
nonce = sha256(
    b"SEALED-TICKET-IV" + key
).digest()[:12]
```

Therefore:

```text
IV =
SHA256("SEALED-TICKET-IV" || key)[0:12]
```

---

# 10. Decrypting the Ticket

The challenge uses AES-GCM:

```python
c = AES.new(
    key,
    AES.MODE_GCM,
    nonce=nonce,
    mac_len=16
)
```

The encrypted ticket and authentication tag are taken from:

```python
ch["z"]["c"]
ch["z"]["t"]
```

and decrypted using:

```python
ticket = c.decrypt_and_verify(
    bytes.fromhex(ch["z"]["c"]),
    bytes.fromhex(ch["z"]["t"])
)
```

Successful authentication confirms that the recovered cryptographic values are correct.

---

# 11. Extracting the Known Plaintext

The decrypted ticket is parsed as JSON:

```python
rec = json.loads(ticket)
```

It contains another encrypted value:

```python
sample_ct = bytes.fromhex(
    rec["x"]["c"]
)
```

The corresponding plaintext is known to be all zero bytes.

For XOR encryption:

```text
C = P XOR K
```

therefore:

```text
K = C XOR P
```

When:

```text
P = 0
```

we get:

```text
K = C
```

Thus the ciphertext itself reveals the keystream:

```python
ks = sample_ct
```

---

# 12. Recovering the Flag

The final flag ciphertext is:

```python
flag_ct = bytes.fromhex(
    ch["y"]["c"]
)
```

The same keystream is then XORed against it:

```python
flag = bytes(
    a ^ b
    for a, b in zip(flag_ct, ks)
)
```

The plaintext is therefore recovered without breaking the underlying cipher.

The solver saves the result to:

```text
flag.txt
```

---

# 13. Complete Attack Chain

```text
                 challenge.json
                       │
                       ▼
               SHA-256 seed hint
                       │
                       ▼
              32-bit brute force
                       │
                       ▼
                     seed
                       │
                       ▼
                      K1
                       │
                       ▼
                   AES-ECB
                       │
                       ▼
             96-bit truncated output
                       │
                       ▼
              2^32 collision search
                       │
                       ▼
                      alt
                       │
              ┌────────┴────────┐
              │                 │
             K1                 n1
              │                 │
              └────────┬────────┘
                       │
                       ▼
              Sealed Ticket Key
                       │
                       ▼
                    AES-GCM
                       │
                       ▼
                  decrypted ticket
                       │
                       ▼
                known plaintext
                       │
                       ▼
              recover keystream
                       │
                       ▼
              XOR flag ciphertext
                       │
                       ▼
                     FLAG
```

---

# 14. Running the Complete Solver

Recommended directory structure:

```text
pancake/
├── README.md
├── challenge.json
├── flag.txt
└── solver/
    ├── solve.py
    ├── brute_seed.c
    └── search.c
```

From the challenge directory:

```bash
cd challenges/pancake
```

Install the Python dependency:

```bash
python3 -m pip install pycryptodome
```

Check OpenSSL:

```bash
openssl version
pkg-config --modversion openssl
```

Compile the seed brute-forcer:

```bash
gcc -O3 -pthread solver/brute_seed.c \
    -o solver/brute_seed \
    $(pkg-config --cflags --libs openssl)
```

Compile the AES collision search:

```bash
gcc -O3 -pthread solver/search.c \
    -o solver/search \
    $(pkg-config --cflags --libs openssl)
```

Run the complete solver:

```bash
python3 solver/solve.py
```

The solver performs the complete attack automatically.

---

# 15. Solver Components

### `solve.py`

Main orchestration script.

Responsibilities:

* Seed setup
* K1 derivation
* AES target generation
* Collision-search invocation
* Collision verification
* AES-GCM key derivation
* Ticket decryption
* Keystream extraction
* Flag recovery

### `brute_seed.c`

Optimized multithreaded SHA-256 brute-force implementation.

Purpose:

```text
2^32 seed search
```

### `search.c`

Optimized multithreaded AES-ECB collision search.

Purpose:

```text
2^32 truncated-output collision search
```

---

# 16. Key Cryptographic Weaknesses

The challenge is breakable because several individually important design choices can be combined.

### Small secret space

The seed is only 32 bits:

```text
2^32
```

making exhaustive search possible.

### Truncated AES output

Only 96 of the 128 AES output bits are compared.

The remaining 32 bits create a practical collision search:

```text
2^32
```

### Collision-dependent key derivation

The alternative value obtained from the truncated AES collision is accepted by the subsequent key derivation.

### Known-plaintext keystream recovery

A ciphertext corresponding to zero plaintext directly exposes the XOR keystream:

```text
C XOR 0 = C
```

### Keystream reuse

The recovered keystream can then be applied to the final ciphertext.

The attack therefore targets the **cryptographic protocol and its composition**, rather than AES or SHA-256 themselves.

---

# 17. Lessons Learned

PANCAKE demonstrates several important principles in practical cryptanalysis:

* Strong primitives do not guarantee a secure protocol.
* Truncating cryptographic outputs can drastically reduce collision resistance.
* Small secret spaces should never be relied upon for security.
* Known plaintext can become dangerous when XOR-based keystreams are reused.
* Authentication mechanisms such as AES-GCM can confirm recovered values, but they do not repair weaknesses in the surrounding protocol.
* Optimized native implementations can make otherwise expensive exhaustive searches practical.

---

# 18. Flag

```text
ASIS{paNc4kE_v3_Lo5t_!t5_n4mE_8Ut___n0T___iTs_89uG!}
```

---

## Conclusion

PANCAKE is a good example of a cryptographic challenge where the individual primitives are not necessarily broken. The exploitation comes from chaining multiple weaknesses:

```text
32-bit seed
    ↓
brute force
    ↓
K1
    ↓
truncated AES-ECB
    ↓
32-bit collision
    ↓
alternative nonce
    ↓
AES-GCM ticket
    ↓
known plaintext
    ↓
keystream recovery
    ↓
XOR
    ↓
FLAG
```

The central lesson is that cryptographic security depends on the **entire construction**, not simply on whether AES and SHA-256 are individually considered secure.
