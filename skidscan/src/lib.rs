pub use skidscan_core::*;
pub use skidscan_macros::*;

#[cfg(feature = "obfuscate")]
pub use obfstr::obfstr;

trait SigScan {
	/// Scans this slice of bytes for a given signature
	fn sigscan(&self, signature: &Signature) -> Option<SignatureRange>;
}
impl<B: AsRef<[u8]>> SigScan for B {
	fn sigscan(&self, signature: &Signature) -> Option<SignatureRange> {
		signature.scan(self.as_ref())
	}
}

#[cfg(test)]
mod test;
