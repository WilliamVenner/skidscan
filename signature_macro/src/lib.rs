#[macro_use]
extern crate syn;

use proc_macro::TokenStream;
use syn::LitStr;

fn signature_internal(tokens: TokenStream, _obfuscate: bool) -> TokenStream {
	let tokens = parse_macro_input!(tokens as LitStr).value();

	let trimmed = tokens.trim();
	if trimmed.is_empty() {
		panic!("Empty signature");
	}

	let mut added_byte = false;
	let mut first = true;

	let mut signature = "::sigscan::Signature::from(vec![".to_string();
	for byte in trimmed.split(' ').into_iter() {
		match (byte.len(), byte) {
			(1, "?") | (2, "??") => if first {
				signature.push_str("None::<u8>,");
			} else {
				signature.push_str("None,");
			},
			(2, _) => {
				added_byte = true;

				#[cfg(feature = "obfuscate")]
				if _obfuscate {
					let byte = u8::from_str_radix(&byte, 16).expect("Invalid byte in signature");
					signature.push_str("Some(sigscan::obfstr!(\"");
					signature.push_str(&byte.to_string());
					signature.push_str("\").parse::<u8>().unwrap()),");
					continue;
				}

				signature.push_str("Some(0x");
				signature.push_str(byte);
				if first {
					signature.push_str("u8");
				}
				signature.push_str("),");
			},
			_ => panic!("Invalid byte in signature")
		}
		first = false;
	}

	if signature.is_empty() {
		panic!("Empty signature")
	} else if !added_byte {
		panic!("Signature only contains ?? bytes")
	} else {
		signature.push_str("])");
		signature.parse().unwrap()
	}
}

#[proc_macro]
pub fn signature(tokens: TokenStream) -> TokenStream {
	signature_internal(tokens, false)
}

#[cfg(feature = "obfuscate")]
#[proc_macro]
pub fn obfsignature(tokens: TokenStream) -> TokenStream {
	signature_internal(tokens, true)
}