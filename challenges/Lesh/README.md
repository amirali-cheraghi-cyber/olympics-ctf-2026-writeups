# Lesh — Write-up

**Category:** Reverse Engineering / Shellcode
**Status:** ✅ Solved during the competition
**Flag:** 🚫 Intentionally omitted

## Challenge Description

> We got an incomplete Lesh shellcode, try to run and catch the flag!

The challenge provides an incomplete shellcode blob encoded as hexadecimal data. The main difficulty is that the shellcode contains misleading execution paths and constructs a fake flag on the stack, while the actual flag is associated with data that is no longer directly recoverable from the provided artifact.

---

## 1. Decoding the Shellcode

The provided `lesh.hex` file contains hexadecimal bytes on a single line.

First, the hex data was converted into a binary file:

```bash
python3 - <<'PY'
from pathlib import Path

h = Path("Lesh/lesh.hex").read_text().strip()
data = bytes.fromhex(h)

Path("lesh.bin").write_bytes(data)

print("hex chars:", len(h))
print("decoded bytes:", len(data))
print("header:", data[:16].hex())
PY
```

Output:

```text
hex chars: 14364
decoded bytes: 7182
header: 31d2b230648b128b520c8b521c8b4208
```

The resulting binary is **7182 bytes**.

---

## 2. Analyzing the Initial Stub

The beginning of the shellcode contains a Windows-style module traversal and API-resolution routine.

The first instructions include:

```asm
xor edx, edx
mov dl, 0x30
mov edx, fs:[edx]
mov edx, [edx+0x0c]
mov edx, [edx+0x1c]
mov eax, [edx+8]
mov esi, [edx+0x20]
mov edx, [edx]
```

The code then checks module names and searches for a module whose name begins with:

```text
Slee
```

After resolving the required function, the shellcode continues into a large region containing many `push` / `pop` / conditional-jump sequences.

These instructions do not immediately reveal meaningful application logic and are largely treated as obfuscation/junk.

---

## 3. Identifying the Infinite Jump

A particularly important location appears at:

```text
0x02a4
```

The bytes there are:

```asm
EB FE
```

which decode to:

```asm
jmp $
```

This is an infinite self-jump.

A normal linear/emulated execution that follows this branch will never reach the interesting part of the shellcode. Therefore, during analysis this path has to be skipped or patched temporarily, for example conceptually as:

```asm
nop
nop
```

or by redirecting execution beyond the loop.

This was one of the key observations required to continue static analysis.

---

## 4. The Interesting Stack Operation

The most important part of the provided shellcode occurs around:

```text
0x169a
```

Immediately before the visible flag-like string is constructed:

```asm
0x169a  add esp, 0x1c
0x169d  lea esp, [esp+0x11]
0x16a1  push 0x5f5f5f5f
0x16a6  push 0x5f5f5f5f
0x16ab  push 0x5f5f5f5f
0x16b0  push 0x5f5f5f67
0x16b5  push 0x616c465f
0x16ba  push 0x65425f74
0x16bf  push 0x6e61435f
0x16c4  push 0x497b5349
0x16c9  push 0x53410000
```

The important observation is that the two stack-pointer modifications occur **before** the pushes:

```asm
add esp, 0x1c
lea esp, [esp+0x11]
```

Together they move the stack pointer by:

```text
0x1c + 0x11 = 0x2d bytes
```

This means that the data previously located in that stack region is discarded from the current stack view before the fake flag is constructed.

That discarded region is significant because the available artifact does not contain those bytes as immediate constants.

---

## 5. Reconstructing the Visible String

The following instructions push immediate 32-bit values onto the stack.

Because x86 is little-endian, every immediate has to be reversed byte-wise when reconstructing the resulting ASCII string.

For example:

```asm
push 0x616c465f
```

is stored as:

```text
_Fla
```

Likewise:

```asm
push 0x65425f74
```

becomes:

```text
t_Be
```

and:

```asm
push 0x6e61435f
```

becomes:

```text
_Can
```

Working through all nine pushes produces the following stack layout:

```text
____
____
____
g___
_Fla
t_Be
_Can
IS{I
\x00\x00AS
```

Since the final push becomes the lowest address on the stack, reading the resulting bytes from `[ESP]` reconstructs a flag-shaped string.

The resulting string begins with:

```text
ASIS{I_Cant_Be_Flag_...
```

This was an important clue, but it is deliberately **not treated as the real flag**.

---

## 6. Recognizing the Decoy

The challenge intentionally makes the reconstructed stack string look like a flag.

However, the surrounding control flow and the stack manipulation indicate that this is a decoy.

The critical clue is:

```asm
add esp, 0x1c
lea esp, [esp+0x11]
```

The shellcode moves past approximately `0x2d` bytes of previously existing stack data before creating the visible string.

Therefore, the interesting data existed **before** the fake flag construction.

The provided `lesh.hex` contains the immediate values used to construct the decoy, but it does not contain a recoverable copy of the earlier runtime stack contents.

---

## 7. Tail Analysis

Near the end of the shellcode another API lookup is performed.

The code resolves a function associated with:

```text
FatalExit
```

and then constructs another stack string:

```asm
push 0x013f3f3f
push 0x47414c46
push 0x20574153
mov ecx, esp
dec byte [ecx+0xb]
```

The resulting text is essentially:

```text
SAW FLAG???
```

This is another useful execution clue, but it is not the actual `ASIS{...}` flag.

---

## 8. Why the Complete Flag Cannot Be Recovered from the Artifact

At this point the analysis establishes three different pieces of information:

| Location                      | Recovered data             | Interpretation                |
| ----------------------------- | -------------------------- | ----------------------------- |
| `0x16a1`                      | `ASIS{I_Cant_Be_Flag_...}` | Decoy                         |
| Tail                          | `SAW FLAG???`              | API argument / execution clue |
| Runtime stack before `0x169a` | Missing                    | Relevant flag data            |

The supplied shellcode is incomplete from the perspective of runtime state.

The missing information is the stack contents that existed immediately before:

```asm
0x169a  add esp, 0x1c
```

To completely reproduce the original solve, the original emulator/solver or a runtime stack snapshot would be required.

In particular, a useful instrumentation point would be immediately before `0x169a`, allowing the emulator to dump the relevant stack region before it is discarded.

---

## 9. Reproduction Script

The supplied decoder can be used to verify the immediate-based reconstruction:

```bash
python3 decode_lesh.py
```

Expected analysis output includes:

```text
decoded bytes 7182
jmp$ offset 0x2a4
push count 9
```

and the reconstructed flag-shaped decoy beginning with:

```text
ASIS{I_Cant_Be_Flag_...
```

This confirms the stack construction without incorrectly treating the decoy as the submission flag.

---

## 10. Conclusion

The solution path was based on reverse-engineering the shellcode rather than simply extracting strings.

The important steps were:

1. Decode the hexadecimal blob into raw shellcode.
2. Analyze the initial Windows API-resolution stub.
3. Identify and bypass the infinite `jmp $` at `0x2a4`.
4. Trace the stack manipulation around `0x169a`.
5. Recognize that the nine `push imm32` instructions construct a deliberate fake flag.
6. Reverse the little-endian immediates to reconstruct the visible stack string.
7. Determine that the meaningful runtime data existed in the stack **before** the fake flag construction.
8. Analyze the tail and identify the `FatalExit` / `SAW FLAG???` path.
9. Conclude that the supplied artifact alone is insufficient to reconstruct the original runtime stack contents.

### Final Status

**Challenge:** Lesh
**Result:** ✅ Solved during the competition
**Score:** 🏆 Obtained during the competition
**Local reproduction:** ⚠️ Partial — the provided artifact does not preserve the complete runtime stack state
**Flag:** 🚫 Omitted from this write-up
