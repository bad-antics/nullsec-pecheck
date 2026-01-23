# NullSec PECheck

Ada PE file analyzer demonstrating strong typing and design by contract.

## Features

- **Strong Static Typing** - Compile-time safety
- **Design by Contract** - Pre/postconditions
- **Tagged Types** - Object-oriented Ada
- **Safe Memory** - No manual allocation
- **Exception Handling** - Robust error handling

## Checks

| Category | Severity | Description |
|----------|----------|-------------|
| ASLR | High | Address randomization |
| DEP/NX | High | Data execution prevention |
| CFG | Medium | Control flow guard |
| Packing | High | High entropy sections |
| Memory | Critical | RWX sections |

## Build

```bash
# With GNAT
gnatmake -O2 pecheck.adb -o pecheck

# With gprbuild
gprbuild -P pecheck.gpr

# Alire package manager
alr build
```

## Usage

```bash
# Analyze PE file
./pecheck malware.exe

# Show sections
./pecheck --sections sample.dll

# JSON output
./pecheck -j suspicious.exe > report.json

# Verbose mode
./pecheck -v program.exe
```

## Output Example

```
File: sample.exe
  Machine:     x64 (64-bit)
  Sections:    5
  Entry Point: 0x1000

Security Features:
  ASLR:  Enabled
  DEP:   Enabled
  CFG:   Disabled

Sections:
  .text      [R-X]  Entropy: 6.20
  .rdata     [R--]  Entropy: 4.80
  UPX0       [RWX]  Entropy: 7.90  ⚠️

Findings:
  [CRITICAL] Memory: Section is both executable and writable
  [HIGH]     Packing: High entropy section detected
```

## Security Checks

- ASLR (Dynamic Base)
- DEP/NX (No Execute)
- CFG (Control Flow Guard)
- SEH (Safe Exception Handling)
- Section entropy analysis
- Packer signature detection
- Suspicious section flags

## Author

bad-antics | [Discord](https://discord.gg/killers)

## License

MIT
