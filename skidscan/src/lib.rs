pub use skidscan_core::*;
pub use skidscan_macros::*;

#[cfg(feature = "obfuscate")]
pub use obfstr::obfstr;

trait SigScan {
	/// Scans this slice of bytes for a given signature
	///
	/// Returns the index of the first occurrence of the signature in the slice, or None if not found
	fn sigscan(&self, signature: &Signature) -> Option<usize>;
}
impl<B: AsRef<[u8]>> SigScan for B {
	fn sigscan(&self, signature: &Signature) -> Option<usize> {
		signature.scan(self.as_ref())
	}
}

#[cfg(test)]
mod test;
