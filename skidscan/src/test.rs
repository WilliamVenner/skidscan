use std::str::FromStr;

use crate::{SigScan, Signature, SignatureParseError, signature};

#[test]
fn test_signature() {
	let mut signature = Signature::default();
	signature.push_any();
	signature.push_byte(0xFF);
	assert_eq!(signature.len(), 2);
}

#[test]
fn test_sigscan() {
	let signature = Signature::from_str("55 8B EC 83 E4 F8 83 EC 78 8B 45 0C B9 ?? ?? 06 10 89 04 24 8B 45 10 89 44 24 04 8D 04 24 56 8B").unwrap();
	let bytes: &[u8] = &[
		0x00, 0x00, 0x00, 0x00, 0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8, 0x83, 0xEC, 0x78, 0x8B, 0x45,
		0x0C, 0xB9, 0x88, 0xA1, 0x06, 0x10, 0x89, 0x04, 0x24, 0x8B, 0x45, 0x10, 0x89, 0x44, 0x24,
		0x04, 0x8D, 0x04, 0x24, 0x56, 0x8B, 0x00, 0x00, 0x00, 0x00,
	];
	assert_eq!(bytes.sigscan(&signature).unwrap(), 4);
	assert_eq!(bytes.sigscan(&signature).unwrap(), 4);
}

#[test]
fn test_sigscan_fail() {
	let signature = Signature::from_str("00").unwrap();
	let bytes: &[u8] = &[
		0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8, 0x83, 0xEC, 0x78, 0x8B, 0x45, 0x0C, 0xB9, 0x88, 0xA1,
		0x06, 0x10, 0x89, 0x04, 0x24, 0x8B, 0x45, 0x10, 0x89, 0x44, 0x24, 0x04, 0x8D, 0x04, 0x24,
		0x56,
	];
	assert!(bytes.sigscan(&signature).is_none());
}

#[test]
fn test_sigscan_invalid() {
	assert_eq!(
		Signature::from_str("??        32 ?? 123 ").unwrap_err(),
		SignatureParseError::InvalidByte
	);
}

#[test]
fn test_only_any_error() {
	assert_eq!(
		Signature::from_str("??").unwrap_err(),
		SignatureParseError::OnlyAny
	);
}

#[test]
fn test_invalid_byte_error() {
	assert_eq!(
		Signature::from_str("LL").unwrap_err(),
		SignatureParseError::InvalidByte
	);
}

#[test]
fn test_empty_error() {
	assert_eq!(
		Signature::from_str("").unwrap_err(),
		SignatureParseError::Empty
	);
}

#[test]
fn test_empty_trim_error() {
	assert_eq!(
		Signature::from_str("       ").unwrap_err(),
		SignatureParseError::Empty
	);
}

#[test]
fn test_ptr_scan() {
	unsafe {
		let bytes: [u8; 32] = [
			0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8, 0x83, 0xEC, 0x78, 0x8B, 0x45, 0x0C, 0xB9, 0x88,
			0xA1, 0x06, 0x10, 0x89, 0x04, 0x24, 0x8B, 0x45, 0x10, 0x89, 0x44, 0x24, 0x04, 0x8D,
			0x04, 0x24, 0x56, 0xFF,
		];
		assert!(Signature::from_str("55 8B EC ?? ?? F8 83")
			.unwrap()
			.scan_ptr(&bytes as *const u8)
			.is_some());
	}
}

#[test]
fn test_ptr_scan_fail() {
	unsafe {
		let bytes: [u8; 32] = [
			0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8, 0x83, 0xEC, 0x78, 0x8B, 0x45, 0x0C, 0xB9, 0x88,
			0xA1, 0x06, 0x10, 0x89, 0x04, 0x24, 0x8B, 0x45, 0x10, 0x89, 0x44, 0x24, 0x04, 0x8D,
			0x04, 0x24, 0x56, 0xFF,
		];
		assert!(Signature::from_str("55 8B EC ?? ?? FF FF")
			.unwrap()
			.scan_ptr(&bytes as *const u8)
			.is_none());
	}
}

#[test]
fn test_proc_macro() {
	assert_eq!(
		Signature::from_str("FF 0E EE 00 ?? ?? 0A").unwrap(),
		signature!("FF 0E EE 00 ?? ?? 0A")
	);
}

#[test]
fn test_mixed_any() {
	Signature::from_str("FF 0E EE 00 ?? ? 0A ?").unwrap();
	Signature::from_str("FF 0E EE 00 ?? ? 0A ??").unwrap();
	Signature::from_str("FF 0E EE 00 ?? ? 0A").unwrap();
}

#[test]
fn test_ida_signature() {
	Signature::from_str("55 8B EC 83 E4 F8 83 EC 78 8B 45 0C B9 ? ? ? ? 89 04 24 8B 45 10 89 44 24 04 8D 04 24 56 8B 75 08 89 44 24 48 8B 45 14 85 C0 57 0F 45 C8 C7 44 24 ? ? ? ? ? 68 ? ? ? ? 8D 44 24 14 89 4C 24 60 50 6A 00 56 C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? E8 ? ? ? ? 8B F8 8D 44 24 20 50 56 E8 ? ? ? ? 8B 76 08 83 C4 18 8B 56 14 3B 56 18 72 08 8B 4D 08 E8 ? ? ? ? 8B C7 5F 5E 8B E5 5D C3").unwrap();
}

#[test]
fn test_ida_proc_macro_signature() {
	assert_eq!(
		Signature::from_str("55 8B EC 83 E4 F8 83 EC 78 8B 45 0C B9 ? ? ? ? 89 04 24 8B 45 10 89 44 24 04 8D 04 24 56 8B 75 08 89 44 24 48 8B 45 14 85 C0 57 0F 45 C8 C7 44 24 ? ? ? ? ? 68 ? ? ? ? 8D 44 24 14 89 4C 24 60 50 6A 00 56 C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? E8 ? ? ? ? 8B F8 8D 44 24 20 50 56 E8 ? ? ? ? 8B 76 08 83 C4 18 8B 56 14 3B 56 18 72 08 8B 4D 08 E8 ? ? ? ? 8B C7 5F 5E 8B E5 5D C3").unwrap(),
		signature!("55 8B EC 83 E4 F8 83 EC 78 8B 45 0C B9 ? ? ? ? 89 04 24 8B 45 10 89 44 24 04 8D 04 24 56 8B 75 08 89 44 24 48 8B 45 14 85 C0 57 0F 45 C8 C7 44 24 ? ? ? ? ? 68 ? ? ? ? 8D 44 24 14 89 4C 24 60 50 6A 00 56 C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? E8 ? ? ? ? 8B F8 8D 44 24 20 50 56 E8 ? ? ? ? 8B 76 08 83 C4 18 8B 56 14 3B 56 18 72 08 8B 4D 08 E8 ? ? ? ? 8B C7 5F 5E 8B E5 5D C3")
	);
}

#[test]
fn test_sized() {
	unsafe {
		let bytes: [u8; 5] = [0xEE, 0x69, 0x42, 0xAA, 0xC5];
		assert!(Signature::from_str("EE ? ?? ? C5")
			.unwrap()
			.scan_ptr(&bytes as *const u8)
			.is_some());
		assert!(Signature::from_str("EE ? ? ? C5")
			.unwrap()
			.scan_ptr(&bytes as *const u8)
			.is_some());
		assert!(Signature::from_str("EE ?? ?? ?? C5")
			.unwrap()
			.scan_ptr(&bytes as *const u8)
			.is_some());
	}
}

#[test]
#[cfg(feature = "obfuscate")]
fn test_obfstr_proc_macro() {
	mod sigscan {
		pub use crate::obfstr;
	}
	assert_eq!(
		Signature::from_str("FF 0E EE 00 ?? ?? 0A").unwrap(),
		crate::obfsignature!("FF 0E EE 00 ?? ?? 0A")
	);
}
