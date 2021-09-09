use crate::{ModuleSigScanError, SigscanPtr, modulescan::Scanner};

type SigByte = Option<u8>;

#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Signature(Vec<SigByte>);
impl Signature {
	/// Creates a signature with a specified capacity of bytes
	#[inline]
	pub fn with_capacity(capacity: usize) -> Self {
		Signature(Vec::with_capacity(capacity))
	}

	#[inline]
	/// Pushes a byte into this signature
	pub fn push_byte(&mut self, byte: u8) {
		self.push(Some(byte));
	}

	#[inline]
	/// Pushes a `??` into this signature
	pub fn push_any(&mut self) {
		self.push(None);
	}

	/// Scans a slice of bytes for the signature
	pub fn scan(&self, bytes: &[u8]) -> Option<usize> {
		let mut iter_bytes = bytes.iter().enumerate();
		let mut start = 0;
		let mut i = 0;
		while i < self.len() {
			let (byte_pos, byte) = iter_bytes.next()?;
			if let Some(sig_byte) = &self.0[i] {
				if sig_byte == byte {
					i += 1;
					if start == 0 {
						start = byte_pos;
					}
				} else {
					start = 0;
					i = 0;
				}
			} else {
				i += 1;
			}
		}
		Some(start)
	}

	/// Increments the pointer until the signature is found/until the signature doesn't match
	pub unsafe fn scan_ptr<P: SigscanPtr>(&self, mut ptr: P) -> Option<P> {
		let mut i = 0;
		while i < self.len() {
			let byte = ptr.byte();
			let sig_byte = &self.0[i];
			if let Some(sig_byte) = sig_byte {
				if *sig_byte != byte {
					#[cfg(debug_assertions)]
					eprintln!("DEBUG: Sigscan found mismatched bytes: 0x{:02X} (sig) != 0x{:02X} (mem) at offset {}", sig_byte, byte, i);
					return None;
				}
			}
			i += 1;
			ptr = ptr.next();
		}
		Some(ptr)
	}

	/// Scan a loaded module for a signature
	pub unsafe fn scan_module<S: AsRef<str>>(&self, module: S) -> Result<*mut u8, ModuleSigScanError> {
		let scanner = Scanner::for_module(module.as_ref()).ok_or(ModuleSigScanError::InvalidModule)?;
		scanner.find(&*self)
	}
}
impl From<Vec<Option<u8>>> for Signature {
	fn from(bytes: Vec<Option<u8>>) -> Self {
		Self(bytes)
	}
}
impl From<&[Option<u8>]> for Signature {
	fn from(bytes: &[Option<u8>]) -> Self {
		Self(bytes.to_vec())
	}
}
impl From<Vec<u8>> for Signature {
	fn from(bytes: Vec<u8>) -> Self {
		Self(bytes.into_iter().map(|byte| Some(byte)).collect())
	}
}
impl From<&[u8]> for Signature {
	fn from(bytes: &[u8]) -> Self {
		Self(bytes.iter().map(|byte| Some(*byte)).collect())
	}
}
impl std::ops::Deref for Signature {
	type Target = Vec<SigByte>;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}
impl std::ops::DerefMut for Signature {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.0
	}
}
impl std::fmt::Debug for Signature {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if !self.is_empty() {
			write!(f, "{:?}", self[0])?;
			for byte in self.iter().skip(1) {
				write!(f, " {:?}", byte)?;
			}
		}
		Ok(())
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SignatureParseError {
	/// A byte in this signature was invalid.
	///
	/// Each byte must be `??` or a 2-digit hex (e.g. `FF`) and optionally separated by spaces (e.g. `FF 00 ?? FF`)
	InvalidByte,

	/// The string was empty.
	Empty,

	/// The signature only contained `??`
	OnlyAny,
}
impl std::str::FromStr for Signature {
	type Err = SignatureParseError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let mut added_byte = false;

		let mut signature = Signature::with_capacity(f32::ceil(s.len() as f32 / 2.) as usize);

		let trimmed = s.trim();
		if trimmed.is_empty() {
			return Err(SignatureParseError::Empty);
		}

		for byte in trimmed.split(' ').into_iter() {
			match (byte.len(), byte) {
				(1, "?") | (2, "??") => signature.push_any(),
				(2, _) => {
					added_byte = true;
					signature.push_byte(u8::from_str_radix(&byte, 16).map_err(|_| SignatureParseError::InvalidByte)?);
				},
				_ => return Err(SignatureParseError::InvalidByte)
			}
		}

		if signature.is_empty() {
			Err(SignatureParseError::Empty)
		} else if !added_byte {
			Err(SignatureParseError::OnlyAny)
		} else {
			signature.shrink_to_fit();
			Ok(signature)
		}
	}
}