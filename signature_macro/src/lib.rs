#[macro_use]
extern crate syn;

use proc_macro::TokenStream;
use syn::LitStr;

const SPACE: &'static char = &' ';

fn signature_internal(tokens: TokenStream, _obfuscate: bool) -> TokenStream {
	let tokens = parse_macro_input!(tokens as LitStr).value();

	let mut added_byte = false;
	let mut first = true;

	let mut signature = "Signature::from(vec![".to_string();
	signature.reserve_exact(f32::ceil(tokens.len() as f32 / 2.) as usize);

	let mut iter = tokens.trim().chars().filter(|char| char != SPACE).into_iter().peekable();
	while let Some(char) = iter.next() {
		if char == '?' {
			if iter.peek() == Some(&'?') {
				iter.next();
			}
			if first {
				signature.push_str("None::<u8>,");
			} else {
				signature.push_str("None,");
			}
		} else {
			added_byte = true;

			#[cfg(feature = "obfuscate")]
			if _obfuscate {
				let mut byte = String::with_capacity(2);
				byte.push(char);
				byte.push(iter.next().expect("Unfinished byte in signature"));

				let byte = u8::from_str_radix(&byte, 16).expect("Invalid byte in signature");

				signature.push_str("Some(sigscan::obfstr!(\"");
				signature.push_str(&byte.to_string());
				signature.push_str("\").parse::<u8>().unwrap()),");
				continue;
			}

			signature.push_str("Some(0x");
			signature.push(char);
			signature.push(iter.next().expect("Unfinished byte in signature"));
			if first {
				signature.push_str("u8");
			}
			signature.push_str("),");
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