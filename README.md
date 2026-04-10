## Basic PatternScanner
Basic Pattern scanner which supports Byte wise and Nibble wise scanning with raw byte/mask combinations as well as derivation from a ida/sigmaker pattern.

NOTE: THIS IS NOT AN IN-PROCESS MEMORY SCANNER, YOU WILL HAVE TO GET THE DATA FOR THE BINARY OR PROCESS YOURSELF

## Usage

This shows basic usage, different architectures will require different patterns.

```rust
use patternscanner::pattern::types::Pattern;
use patternscanner::scanner::scanner::{
    scan_all, scan_all_with_base, scan_all_iter,
};

// This data has to be retrieved before usage, via ReadMemory or similar methods
let data: &[u8] = &[/* memory region */];

// IDA-style pattern
let p = Pattern::from_ida_str("48 89 5C 24 ?? 48 83 EC ??").unwrap();

// Nibble-level wildcards
let p_nibble = Pattern::from_ida_like_with_nibble("4? 8? ?C").unwrap();

// Raw bytes + mask
let p_raw = Pattern::new_with_byte_mask(
    vec![0x48, 0x89, 0x00, 0x48],
    vec![0xFF, 0xFF, 0x00, 0xFF],
).unwrap();

// Collect all matches
for m in scan_all(data, &p) {
    println!("{:#x}", m.offset);
}

// With a module base address
let base: u64 = 0x140000000;
for m in scan_all_with_base(data, &p, base) {
    println!("offset {:#x}  va {:#x}", m.offset, m.address);
}

// Lazy — stop after the first hit
if let Some(m) = scan_all_iter(data, &p).next() {
    println!("first match at {:#x}", m.offset);
}

// Check a single known offset
assert!(p.matches_at(data, 0x1000));
```