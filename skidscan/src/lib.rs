pub use skidscan_core::*;
pub use skidscan_macros::*;

#[cfg(feature = "obfuscate")]
pub use obfstr::obfstr;

trait SigScan {
	/// Scans this slice of bytes for a given signature
	fn sigscan(&self, signature: &Signature) -> Option<SignatureRange>;
}
impl SigScan for dyn AsRef<[u8]> {
	fn sigscan(&self, signature: &Signature) -> Option<SignatureRange> {
		signature.scan(self.as_ref())
	}
}
impl SigScan for &[u8] {
	fn sigscan(&self, signature: &Signature) -> Option<SignatureRange> {
		signature.scan(self)
	}
}
impl SigScan for Vec<u8> {
	fn sigscan(&self, signature: &Signature) -> Option<SignatureRange> {
		signature.scan(&self)
	}
}

#[cfg(test)]
mod test;
