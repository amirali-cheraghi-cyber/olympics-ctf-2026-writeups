# ASIS-ARCH

> **OLYMPICS CTF 2026 — Reverse Engineering Write-up**

## Challenge Information

| Field      | Value                                          |
| ---------- | ---------------------------------------------- |
| Challenge  | ASIS-ARCH                                      |
| Category   | Reverse Engineering                            |
| Difficulty | —                                              |
| Status     | Solved                                         |
| Flag       | `ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}` |

---

## Overview

ASIS-ARCH is a reverse-engineering challenge built around a custom 16-bit virtual architecture.

Instead of directly executing the provided ROM using a standard CPU architecture, the challenge uses a custom instruction set and an encoded instruction format.

The main difficulty comes from the fact that instructions cannot simply be read as normal opcodes. The solver has to reconstruct several layers of the virtual machine:

1. ROM loading
2. Entry-point recovery
3. Instruction decoding
4. Byte permutation
5. Per-address decoding parameters
6. Opcode recovery
7. Register decoding
8. Immediate reconstruction
9. Instruction classification
10. Analysis of the generated VM code

The provided solver automates this process and produces a disassembly-like representation of the VM instructions.

---

# 1. Challenge Structure

The challenge ROM is loaded from:

```text
ASIS-Arch/
└── challenge.rom
```

The solver is:

```text
solve_asis.py
```

A basic directory structure for the write-up is:

```text
asis-arch/
├── README.md
├── challenge.rom
└── solver/
    └── solve_asis.py
```

---

# 2. Initial ROM Analysis

The solver reads the ROM using:

```python
def load_rom(path):
    data = Path(path).read_bytes()
```

The first `0x20` bytes are treated separately from the executable payload:

```python
payload = data[0x20:]
```

A 64 KiB virtual memory space is then created:

```python
mem = bytearray(0x10000)
mem[:len(payload)] = payload
```

Therefore, the VM operates on a:

```text
0x0000 – 0xFFFF
```

address space.

---

# 3. Recovering the Entry Point

The initial program counter is not stored as a normal little-endian or big-endian address.

Two bytes from the ROM header are transformed using rotations:

```python
al = rol8(data[9], 4)
dl = rol8(data[8], 4)
```

They are then combined:

```python
pc = rol16((al << 8) | dl, 5)
```

This gives the initial VM program counter.

The important observation is that the ROM contains an encoded entry point rather than directly exposing the address.

---

# 4. Custom Instruction Encoding

Each instruction occupies four bytes:

```python
raw = bytes(mem[pc:pc+4])
```

However, the four bytes are not stored in their logical order.

A permutation is selected based on the current program counter.

The solver defines four possible permutations:

```python
PERM = [
    bytes([0,1,2,3]),
    bytes([2,0,3,1]),
    bytes([3,2,1,0]),
    bytes([1,3,0,2]),
]
```

The selected permutation is determined using:

```python
ax = ((pc ^ 0x9e37) * 0x1039 + 0x79b9) & 0xffff
sel = (ax >> 14) & 3
```

Then:

```python
perm = PERM[sel]
```

is applied to the instruction bytes.

This means the same byte position does not necessarily represent the same logical field for every instruction.

---

# 5. Address-Dependent Instruction Decoding

The decoder derives an additional value from the current program counter:

```python
di = rol16(ax, 5)
```

The instruction bytes are then transformed using this value.

For example, the opcode byte is reconstructed with:

```python
al = ((0x5d * pc) ^ di ^ b2) & 0xff
al = rol8(al, (di >> 5) & 0xff) ^ 0x6d
opc = al
```

This is an address-dependent encoding scheme.

Consequently, simply extracting the first byte of an instruction and treating it as an opcode would not work.

The decoder must know the current VM program counter before the instruction can be interpreted.

---

# 6. Register Encoding

The destination register is also obfuscated.

First, an intermediate value is calculated:

```python
eax = ((pc * 7) ^ (di >> 2) ^ r9) & 0xff
eax = ((eax * 5) ^ 3) & 7
```

The final destination register is obtained with:

```python
dst = ((eax * 5) ^ 3) & 7
```

The solver therefore converts the encoded register information back into a VM register index.

---

# 7. Immediate Value Reconstruction

The remaining bytes are used to reconstruct a 16-bit immediate value.

The relevant transformation is:

```python
r8 = rol8(
    (r8 ^ (di & 0xff)) & 0xff,
    4
)

dl = rol8(
    b3 ^ ((di >> 8) & 0xff),
    4
)

imm = rol16(
    (dl << 8) | r8,
    5
)
```

This produces the decoded immediate value:

```text
imm ∈ [0x0000, 0xFFFF]
```

The result of the decoder is therefore:

```python
return opc, dst, imm
```

giving the three most important components of a decoded VM instruction:

```text
opcode
destination register
immediate / operand
```

---

# 8. Reconstructing the Instruction Set

Once the decoding layer is reversed, the opcode values can be mapped to instruction names.

The solver defines:

```python
OP = {
    16:'NOP',
    21:'MOV_IMM',
    33:'ADD_IMM',
    39:'SUB_IMM',
    50:'XOR_IMM',
    56:'AND_IMM',
    68:'ROL_IMM',
    75:'MOV_RR',
    80:'ADD_RR',
    86:'SUB_RR',
    92:'XOR_RR',
    99:'LDB',
    105:'STB',
    113:'LDW',
    119:'STW',
    128:'JMP',
    134:'JZ',
    140:'JNZ',
    146:'PUSH',
    152:'POP',
    161:'CALL',
    167:'RET',
    179:'IN',
    185:'OUT',
    194:'SBOX',
    254:'HLT',
}
```

This effectively reconstructs the custom instruction set.

The VM supports arithmetic, bitwise operations, memory access, control flow, stack operations, I/O, and an S-box operation.

---

# 9. Important VM Instructions

The recovered instruction set contains several groups.

### Arithmetic

```text
ADD_IMM
SUB_IMM
ADD_RR
SUB_RR
```

### Bitwise

```text
XOR_IMM
AND_IMM
XOR_RR
```

### Rotation

```text
ROL_IMM
```

### Register operations

```text
MOV_IMM
MOV_RR
```

### Memory

```text
LDB
STB
LDW
STW
```

### Control Flow

```text
JMP
JZ
JNZ
CALL
RET
```

### Stack

```text
PUSH
POP
```

### I/O

```text
IN
OUT
```

### Cryptographic primitive

```text
SBOX
```

### Program termination

```text
HLT
```

---

# 10. Stage 1 — Recovering Constants

After reconstructing the decoder, the solver searches the initial code region:

```python
pc = 0x24

while pc < 0x400:
```

It specifically searches for instructions matching:

```python
MOV_IMM
```

where the destination is register `r6` and the immediate points into:

```text
0xC000 – 0xC02A
```

The relevant condition is:

```python
if o == 21 and d == 6 and 0xc000 <= imm <= 0xc02a:
```

The solver then examines the following six instructions:

```python
ops = [
    decode(mem, pc + 4*i)
    for i in range(6)
]
```

and identifies another `MOV_IMM` instruction targeting register `r1`:

```python
if ops[3][0] == 21 and ops[3][1] == 1:
```

The resulting constants are stored in:

```python
C[imm] = ops[3][2]
```

This allows the solver to recover the initial constant table stored around:

```text
0xC000
```

through:

```text
0xC02A
```

---

# 11. Stage 1 Boundary

The solver then locates the end of this initialization stage.

It searches for:

```text
MOV_IMM r6, 0xC02A
```

and defines:

```python
stage1_end = pc + 24
```

The analysis then continues from this address.

This separates the initial constant-generation/loading stage from the main VM logic.

---

# 12. Disassembling the Main Code

After Stage 1, the solver begins printing decoded VM instructions:

```python
for i in range(400):
    o, d, imm = decode(mem, pc)
```

Each opcode is converted into a human-readable name:

```python
nm = name(o)
```

The output contains:

```text
address
instruction
destination register
immediate
```

For register-to-register operations, the solver additionally reconstructs the source register:

```python
src = enc_reg(imm & 7)
```

For memory operations, the decoded address expression is displayed as:

```text
[rX + offset]
```

This effectively turns the custom encoded ROM into a readable pseudo-disassembly.

---

# 13. Analysis of the Memory Layout

The solver identifies a dedicated region beginning around:

```text
0xC000
```

which is used during the initial stage.

The analysis therefore separates:

```text
Code region
    ↓
Instruction decoding
    ↓
Initialization
    ↓
Constant area around 0xC000
    ↓
Main VM execution
```

This is important because attempting to analyze the entire ROM as a flat stream of instructions would mix initialization data and executable logic.

---

# 14. S-Box Reconstruction

The ROM-based architecture contains a 256-byte substitution box:

```python
SBOX = bytes.fromhex(...)
```

The inverse S-box is reconstructed automatically:

```python
INV = [0] * 256

for i, b in enumerate(SBOX):
    INV[b] = i
```

The solver also defines word-level transformations:

```python
def sbox2(w):
    return (
        (SBOX[(w >> 8) & 0xff] << 8)
        | SBOX[w & 0xff]
    )
```

and:

```python
def unsbox2(w):
    return (
        (INV[(w >> 8) & 0xff] << 8)
        | INV[w & 0xff]
    )
```

This indicates that the VM's cryptographic/data-transformation logic operates on individual bytes while also providing a 16-bit representation.

---

# 15. Linear Mixing Operation

The solver defines another transformation:

```python
def mix(x):
    return x ^ rol16(x, 5) ^ rol16(x, 11)
```

This operation is linear over the 16-bit state when interpreted over GF(2).

The presence of rotations combined with XOR is characteristic of lightweight bit-level mixing.

The solver comments on the possibility of treating the transformation as an involution and notes that its inverse can be determined computationally.

---

# 16. Why the Decoder Was the Main Challenge

The challenge intentionally prevents straightforward disassembly.

The instruction stream is protected by several layers:

```text
Raw ROM bytes
     │
     ▼
Address-dependent value
     │
     ▼
Byte permutation
     │
     ▼
Byte transformations
     │
     ▼
Opcode recovery
     │
     ▼
Register recovery
     │
     ▼
Immediate recovery
     │
     ▼
Custom VM instruction
```

Without reversing the decoder, the ROM appears to be essentially arbitrary binary data.

The key breakthrough was therefore to stop treating the ROM as a conventional executable and instead reconstruct the virtual instruction format.

---

# 17. Running the Solver

From the challenge directory:

```bash
cd challenges/asis-arch
```

Run the solver:

```bash
python3 solver/solve_asis.py
```

If the ROM is stored in the expected location:

```text
ASIS-Arch/challenge.rom
```

the solver loads it automatically.

The solver expects:

```text
/home/workdir/artifacts/asisarch/ASIS-Arch/challenge.rom
```

in the original analysis environment.

When adapting the solver for GitHub, it is recommended to replace the hard-coded path with a relative path, for example:

```python
from pathlib import Path

ROM = Path(__file__).parent.parent / "challenge.rom"

mem, entry = load_rom(ROM)
```

This makes the write-up reproducible on another machine.

---

# 18. Useful Commands

Check the challenge files:

```bash
find . -maxdepth 3 -type f -print
```

Inspect the ROM size:

```bash
ls -lh challenge.rom
```

Identify the file:

```bash
file challenge.rom
```

Inspect the first bytes:

```bash
xxd -l 64 challenge.rom
```

Run the decoder:

```bash
python3 solver/solve_asis.py
```

Save the disassembly output:

```bash
python3 solver/solve_asis.py | tee disassembly.txt
```

Search the resulting output:

```bash
grep -n "SBOX\|JNZ\|HLT\|CALL\|RET" disassembly.txt
```

---

# 19. Solver Logic

The complete solver can be summarized as:

```text
challenge.rom
      │
      ▼
Load ROM
      │
      ▼
Recover initial PC
      │
      ▼
Read 4-byte instruction
      │
      ▼
Calculate address-dependent decoder state
      │
      ▼
Select byte permutation
      │
      ▼
Recover opcode
      │
      ▼
Recover destination register
      │
      ▼
Recover immediate
      │
      ▼
Map opcode → VM instruction
      │
      ▼
Recover initialization constants
      │
      ▼
Disassemble main VM code
      │
      ▼
Analyze S-box / mixing operations
      │
      ▼
Recover challenge logic
```

---

# 20. Files Used

### `solve_asis.py`

Main reverse-engineering script.

It implements:

* ROM loading
* Entry-point recovery
* Instruction decoding
* Opcode mapping
* Register decoding
* Immediate reconstruction
* Constant extraction
* VM disassembly
* S-box helpers
* Mixing operations

### `challenge.rom`

The custom VM ROM supplied by the challenge.

---

# 21. Reproducibility

The original solver contains absolute paths such as:

```text
/home/workdir/artifacts/asisarch/ASIS-Arch/challenge.rom
```

For a public GitHub write-up, these paths should be converted to relative paths.

Recommended structure:

```text
asis-arch/
├── README.md
├── challenge.rom
└── solver/
    └── solve_asis.py
```

Then execute:

```bash
python3 solver/solve_asis.py
```

This avoids dependencies on the original CTF working directory.

---

# 22. Flag

The recovered flag is:

```text
ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}
```

---

# 23. Takeaways

The main lesson from ASIS-ARCH is that custom virtual machines can make reverse engineering significantly harder by separating the physical byte representation from the logical instruction representation.

The important steps were:

1. Identify the ROM structure.
2. Recover the encoded entry point.
3. Reverse the address-dependent decoder.
4. Recover the byte permutation.
5. Reconstruct the opcode.
6. Decode registers and immediates.
7. Reconstruct the custom instruction set.
8. Identify initialization data.
9. Disassemble the VM code.
10. Analyze the cryptographic transformations.

The challenge is therefore primarily a **custom VM / instruction-decoding reverse-engineering problem**, with additional cryptographic transformations embedded inside the architecture.

---

## Flag

```text
ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}
```
