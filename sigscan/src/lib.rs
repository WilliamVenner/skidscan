pub use sigscan_core::*;
pub use signature_macro::*;

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

trait SigScanPtr {
	/// Increments the pointer until the signature is found, or until the signature doesn't match.
	///
	/// Returns `Some(*const u8)` where the returned pointer is the end of the found signature.
	unsafe fn sigscan(self, signature: &Signature) -> Option<*const u8>;
}
impl SigScanPtr for *const u8 {
	unsafe fn sigscan(self, signature: &Signature) -> Option<*const u8> {
		signature.scan_ptr(self)
	}
}
impl SigScanPtr for *mut u8 {
	unsafe fn sigscan(self, signature: &Signature) -> Option<*const u8> {
		signature.scan_ptr(self as *const u8)
	}
}

#[cfg(test)]
mod test;
