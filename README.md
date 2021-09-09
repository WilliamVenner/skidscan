# skidscan

Quick & dirty Rust sigscanning crate.

# Features

* Cross-platform
* Scan for patterns from a pointer
* Scan for patterns in a byte slice
* Scan for patterns in a loaded shared library (.so/.dll)
* "Obfuscated signatures" using [obfstr](https://crates.io/crates/obfstr)

# Usage

```rust
let sig = signature!("40 53 48 83 EC 20 48 8B 01 48 8B D9 48 89 91 ? ? ? ? FF 90 ? ? ? ? 33 D2");
let sig = obfsignature!("40 53 48 83 EC 20 48 8B 01 48 8B D9 48 89 91 ? ? ? ? FF 90 ? ? ? ? 33 D2"); // "Obfuscated" signature

let result: Result<*mut u8, ModuleSigScanError> = sig.scan_module("path or module name");
let result: Option<usize> = sig.scan_ptr(0xDEADBEEF as *mut u8);
let result: Option<usize> = sig.scan(&[0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0x01, 0x48, 0x8B, 0xD9, 0x48, 0x89, 0x91, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x90, 0x00, 0x00, 0x00, 0x00, 0x33, 0xD2]);
```

## Signatures

Signatures are constructed as a series of `Option<u8>`.

`None` represents a `?`: any byte, so long as it is present.

`Some(u8)` represents this byte exactly.

For example, `signature!("48 89 91 ? ? ?")` becomes `[Some(0x48), Some(0x89), Some(0x91), None, None, None]`

## Obfuscated Signatures

You can construct an "obfuscated" signature using [obfstr](https://crates.io/crates/obfstr) with the `obfuscate` crate feature.

Obfuscated signatures are constructed, for each byte: `Some(obfstr!("0xFF").parse::<u8>())`

For example, `signature!("48 89 91 ? ? ?")` becomes `[Some(obfstr!("0x48").parse::<u8>()), Some(obfstr!("0x89").parse::<u8>()), Some(obfstr!("0x91").parse::<u8>()), None, None, None]`
