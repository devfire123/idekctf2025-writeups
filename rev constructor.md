# Constructor - Reverse Engineering CTF Writeup

**Challenge**: Constructor  
**Category**: Reverse Engineering  
**Points**: 100  
**Solves**: 315  
**Author**: Zerotistic  

## Challenge Description
```
Heard of constructor?
flag format is idek{fakeflag}
```

## Initial Analysis

### File Information
```bash
$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

The binary is:
- **ELF 64-bit**: Linux executable for x86-64 architecture
- **Statically linked**: All dependencies are included in the binary
- **Stripped**: No debug symbols or function names are preserved

### Basic Testing
```bash
$ ./chall
👀

$ ./chall test
Wrong!
```

The program expects a command line argument and outputs "Wrong!" for incorrect input, suggesting it's checking for a specific flag.

## Reverse Engineering Approach

### 1. String Analysis
```bash
$ strings chall
...
Correct!
Wrong!
...
```

Found key strings that indicate the program validates input and outputs success/failure messages.

### 2. Section Analysis
```bash
$ readelf -S chall
Section Headers:
  [ 1] .init             PROGBITS         0000000000401000
  [ 2] .text             PROGBITS         0000000000401010
  [ 6] .init_array       INIT_ARRAY       0000000000404fb0
  [ 7] .fini_array       FINI_ARRAY       0000000000404fc8
  [ 4] .rodata           PROGBITS         0000000000403000
```

The presence of `.init_array` is crucial - this section contains function pointers to constructor functions that run before `main()`.

### 3. Constructor Functions Discovery
```bash
$ objdump -s chall | grep -A 5 -B 5 "404fb0"
Contents of section .init_array:
 404fb0 90124000 00000000 30104000 00000000  ..@.....0.@.....
 404fc0 50104000 00000000                    P.@.....
```

The `.init_array` contains three function pointers:
- `0x401290` (90124000 in little-endian)
- `0x401030` (30104000 in little-endian)
- `0x401050` (50104000 in little-endian)

### 4. Constructor Function Analysis

#### First Constructor (0x401290)
```assembly
401290: f3 0f 1e fa             endbr64
401294: e9 77 ff ff ff          jmp    0x401210
```
This function just jumps to another location.

#### Second Constructor (0x401030)
```assembly
401030: f3 0f 1e fa             endbr64
401034: c7 44 24 fc 00 00 00    movl   $0x0,-0x4(%rsp)
40103b: 00 
40103c: 8b 44 24 fc             mov    -0x4(%rsp),%eax
401040: 83 c0 42                add    $0x42,%eax
401043: 89 44 24 fc             mov    %eax,-0x4(%rsp)
401047: c3                      ret
```
This function performs simple arithmetic: adds `0x42` (66) to a value.

#### Third Constructor (0x401050) - The Key Function
```assembly
401050: f3 0f 1e fa             endbr64
401054: 41 55                   push   %r13
401056: 41 54                   push   %r12
401058: 55                      push   %rbp
401059: 53                      push   %rbx
40105a: 48 81 ec 00 10 00 00    sub    $0x1000,%rsp
40106a: 31 c9                   xor    %ecx,%ecx          ; ecx = 0
40106c: 48 8d 1d cd 40 00 00    lea    0x40cd(%rip),%rbx  ; rbx = 0x405140 (dest)
401073: 48 8d 3d c6 1f 00 00    lea    0x1fc6(%rip),%rdi  ; rdi = 0x403040 (src)
40108b: 31 c0                   xor    %eax,%eax          ; rax = 0 (counter)
401090: 0f b6 14 07             movzbl (%rdi,%rax,1),%edx ; load byte from src
401094: 48 89 c6                mov    %rax,%rsi           ; rsi = rax
401097: 48 d1 ee                shr    $1,%rsi             ; rsi = rax >> 1
40109a: 31 ca                   xor    %ecx,%edx           ; edx ^= ecx
40109c: 83 c1 1f                add    $0x1f,%ecx          ; ecx += 31
40109f: 31 f2                   xor    %esi,%edx           ; edx ^= rsi
4010a1: 83 f2 5a                xor    $0x5a,%edx          ; edx ^= 0x5a
4010a4: 88 14 03                mov    %dl,(%rbx,%rax,1)  ; store result
4010a7: 48 83 c0 01             add    $0x1,%rax           ; rax++
4010ab: 48 83 f8 2a             cmp    $0x2a,%rax          ; compare with 42
4010af: 75 df                   jne    0x401090            ; loop if not equal
```

### 5. Encrypted Data Location
```bash
$ objdump -s chall | grep -A 5 -B 5 "403040"
Contents of section .rodata:
 403040 3321006d 5fab86b4 d42d363a 4e908ce3  3!.m_....-6:N...
 403050 cc2e096c 49b88ff7 cc224e4d 5eb880cb  ...lI...."NM^...
 403060 d3da2029 7002b7d1 b7c4               .. )p.....
```

The encrypted data starts at address `0x403040`:
```
33 21 00 6d 5f ab 86 b4 d4 2d 36 3a 4e 90 8c e3 
cc 2e 09 6c 49 b8 8f f7 cc 22 4e 4d 5e b8 80 cb 
d3 da 20 29 70 02 b7 d1 b7 c4
```

## Decryption Algorithm

Based on the assembly analysis, the decryption algorithm is:

1. **Initialize**: `ecx = 0`, `rax = 0` (counter)
2. **For each byte at position `i` (0 to 41)**:
   - Load encrypted byte from `0x403040 + i`
   - Calculate `half_i = i // 2`
   - Decrypt: `byte = byte ^ ecx ^ half_i ^ 0x5a`
   - Store result at `0x405140 + i`
   - Update: `ecx += 0x1f` (31)

## Python Decryption Script

```python
#!/usr/bin/env python3

# Encrypted data from address 0x403040
encrypted = bytes.fromhex("3321006d5fab86b4d42d363a4e908ce3cc2e096c49b88ff7cc224e4d5eb880cbd3da20297002b7d1b7c4")

# Decryption algorithm from the constructor function
# ecx starts at 0
# For each byte at position i:
#   byte = byte ^ ecx ^ (i//2) ^ 0x5a
#   ecx += 0x1f (31)
decrypted = bytearray()

ecx = 0
for i in range(len(encrypted)):
    # Get the encrypted byte
    encrypted_byte = encrypted[i]
    # Calculate half of position
    half_i = i // 2
    # Decrypt: byte ^ ecx ^ (i//2) ^ 0x5a
    decrypted_byte = encrypted_byte ^ ecx ^ half_i ^ 0x5a
    # Ensure byte is in range 0-255
    decrypted_byte = decrypted_byte & 0xFF
    decrypted.append(decrypted_byte)
    # Update ecx for next iteration
    ecx += 0x1f

print("Decrypted flag:", decrypted.decode('ascii', errors='ignore'))
```

## Solution Verification

```bash
$ python3 decrypt.py
Decrypted flag: idek{he4rd_0f_constructors?_now_you_d1d!!}

$ ./chall "idek{he4rd_0f_constructors?_now_you_d1d!!}"
Correct!
```

## Key Learning Points

1. **Constructor Functions**: In C++, constructor functions (defined with `__attribute__((constructor))`) are called automatically before `main()`. They are stored in the `.init_array` section.

2. **Static Linking**: The binary contains all dependencies, making it larger but more portable. This also means no external library calls to trace.

3. **Stripped Binaries**: Without symbols, we need to rely on:
   - String analysis
   - Section analysis
   - Cross-referencing addresses
   - Understanding common patterns

4. **XOR Encryption**: The flag was encrypted using XOR operations with a counter and position-based keys, a common technique in CTF challenges.

## Flag

**idek{he4rd_0f_constructors?_now_you_d1d!!}**

## Tools Used

- `file` - File type identification
- `strings` - String extraction
- `readelf` - ELF file analysis
- `objdump` - Disassembly and section analysis
- `gdb` - Debugging (attempted)
- Python - Custom decryption script

## Methodology

1. **Static Analysis**: Examined file structure and sections
2. **Dynamic Analysis**: Tested program behavior with different inputs
3. **Reverse Engineering**: Disassembled and analyzed constructor functions
4. **Algorithm Reconstruction**: Replicated the decryption logic in Python
5. **Verification**: Confirmed the solution works with the original binary

This challenge demonstrates the importance of understanding program initialization mechanisms and how constructor functions can be used to hide or obfuscate program logic. 