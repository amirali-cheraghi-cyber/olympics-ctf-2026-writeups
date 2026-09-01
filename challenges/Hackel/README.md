# Hackel 🗝️

**Category:** Crypto
**Difficulty:** —

## Description

Hackel is a cryptographic challenge based on algebraic group presentations.

The service exposes a set of training samples and encrypted words, together with a homomorphic concatenation oracle and several ways of attempting to unlock the vault.

The challenge claims that the underlying representation has an enormous search space. However, the provided training data leaks enough information to recover a much simpler representation.

---

## Enumeration

Connecting to the service:

```bash
nc 65.109.208.91 3771
```

The service provides the following options:

```text
[1] View Public Parameters & Relations
[2] View Training Samples & Encrypted Flag Words
[3] Homomorphic Word Concatenation Oracle
[4] Submit Recovered Equivalent Key (Unlock Flag)
[5] Interactive Speed Challenge (Unlock Flag)
[6] Exit
```

The most interesting option is:

```text
2] View Training Samples & Encrypted Flag Words
```

which returns:

```text
Zero Training Words (16)
One Training Words (16)
Encrypted Flag Words (496)
```

---

## Analyzing the Training Data

The zero-training samples consist only of `a` characters:

```text
a
aa
aaaa
aaaaaa
aaaaaaa
aaaaaaaa
aaaaaaaaa
...
```

All of these evaluate to the identity element.

This indicates that `a` contributes no information to the resulting representation.

Therefore:

```text
a → 0
```

The one-training samples, on the other hand, contain `b`:

```text
b
ab
aab
aaaab
aaaaaab
...
```

These evaluate to the non-zero element.

This gives the important relation:

```text
b → 1
```

The exact number of `a` characters is irrelevant.

---

## Recovering the Encoding

The training samples reveal that the representation is effectively binary.

Only the parity of the number of `b` characters matters:

```python
value = word.count("b") % 2
```

Therefore:

```text
even number of b → 0
odd number of b  → 1
```

For example:

```text
aaaaaa → 0
aaaa   → 0
aab    → 1
aaaaab → 1
b      → 1
```

The homomorphic concatenation behavior is consistent with this representation, since combining two words corresponds to combining their underlying binary values.

The supposedly huge search space is therefore unnecessary to explore.

---

## Recovering the Encrypted Data

The service provides **496 encrypted words**.

Since each word represents one bit:

```text
496 bits
```

and:

```text
496 / 8 = 62 bytes
```

we can process the encrypted words eight at a time.

For each group of eight words, the recovered bits are assembled into one byte:

```python
def decode_word(word):
    return word.count("b") % 2


flag_bytes = []

for i in range(0, len(encrypted), 8):
    byte = 0

    for j in range(8):
        bit = decode_word(encrypted[i + j])
        byte = (byte << 1) | bit

    flag_bytes.append(byte)

flag = ''.join(chr(b) for b in flag_bytes)

print(flag)
```

The resulting plaintext begins with the expected CTF format:

```text
ASIS{
```

confirming that the recovered representation is correct.

---

## Solve

The complete attack can be summarized as:

```text
Training Samples
       ↓
a → Identity
       ↓
b → Non-zero element
       ↓
Parity of b determines the value
       ↓
count(b) % 2
       ↓
496 encrypted words
       ↓
496 bits
       ↓
8 bits → 1 byte
       ↓
ASCII
       ↓
Flag
```

The key insight is that the advertised large algebraic search space can be bypassed entirely by recovering the leaked representation from the training samples.

---

## Flag

```text
ASIS{sEm1d!r3c7_gr0uP_pr3S3nt4T10n____k3y___r3C0verY_4Tt4ck!!}
```

## Conclusion

Instead of attempting to brute-force the claimed enormous key space, the training data can be used to recover the underlying binary representation directly.

The challenge reduces to identifying that `a` represents the identity and that the parity of `b` determines the resulting value. The 496 resulting bits can then be reconstructed into 62 ASCII bytes, revealing the flag.
