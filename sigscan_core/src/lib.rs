use scanner::Scanner;

mod scanner;

pub type SignatureRange = (usize, usize);
pub type SignatureByte = Option<u8>;

#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Signature(Vec<SignatureByte>);
impl Signature {
	/// Creates a signature with a specified capacity of bytes
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
	pub fn scan(&self, bytes: &[u8]) -> Option<SignatureRange> {
		let mut iter_bytes = bytes.iter().enumerate();
		let mut start = 0;
		let mut i = 0;
		while i < self.len() {
			let (byte_pos, byte) = iter_bytes.next()?;
			let sig_byte = &self.0[i];
			if let Some(sig_byte) = sig_byte {
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
		Some((start, i))
	}

	/// Increments the pointer until the signature is found/until the signature doesn't match
	pub unsafe fn scan_ptr(&self, mut ptr: *const u8) -> Option<*const u8> {
		let mut i = 0;
		while i < self.len() {
			let byte = *ptr;
			let sig_byte = &self.0[i];
			if let Some(sig_byte) = sig_byte {
				if *sig_byte != byte {
					#[cfg(debug_assertions)]
					eprintln!("DEBUG: Sigscan found mismatched bytes: 0x{:02X} (sig) != 0x{:02X} (mem) at offset {}", sig_byte, byte, i);
					return None;
				}
			}
			i += 1;
			ptr = ptr.add(1);
		}
		Some(ptr)
	}

	/// Scan a loaded module for a signature
	pub unsafe fn scan_module<S: AsRef<str>>(&self, module: S) -> Result<*mut u8, ModuleSigScanError> {
		let scanner = Scanner::for_module(module.as_ref()).ok_or(ModuleSigScanError::InvalidModule)?;
		scanner.find(&*self).ok_or(ModuleSigScanError::NotFound)
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
impl std::ops::Deref for Signature {
	type Target = Vec<SignatureByte>;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ModuleSigScanError {
	/// Failed to find the signature
	NotFound,

	/// Unable to open the specified module
	InvalidModule,
}