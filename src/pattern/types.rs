use std::borrow::Cow;

use crate::error::{Error, InternalResult};

/// Represents the rough type of pattern
/// Currently basically unsused, should be used if more kinds of patterns should be supported
#[derive(Debug)]
pub enum PatternKind {
	Ida,
}

/// Represents the type of Pattern, if its a Raw String or a Byte Array with Mask,
/// RawString is basically unused at the moment since all string are "compiled" to the Byte Array
/// with Mask form.
#[derive(Debug)]
pub enum PatternRepr {
	RawString,
	BytesWithMask,
}

/// Mask type to differentiate between a full 8bit Byte Mask or a 4bit Nibble Mask
pub enum MaskType {
	Byte,
	Nibble,
}

/// Holds Pattern Bytes, Mask, Type and the Nibble/Byte Compat mask
pub struct Pattern {
	pub bytes: Vec<u8>,
	pub mask: Vec<u8>,
	pub mask_type: MaskType,
	// Precomputed bytes[i] & mask[i]; same formula works for byte and nibble masks.
	pub(crate) masked_bytes: Vec<u8>,
}

impl Pattern {
	/// Create a new Pattern via Bytes, Mask and Type of Mask directly
	pub fn new(bytes: Vec<u8>, mask: Vec<u8>, mask_type: MaskType) -> InternalResult<Self> {
		if bytes.len() > mask.len() {
			Err(Error::InvalidPattern {
				kind: PatternKind::Ida,
				repr: PatternRepr::BytesWithMask,
				hint: Some(Cow::Owned(
					"Mask bytes must be atleast the same amount as the bytes of the pattern.".to_owned(),
				)),
			})
		} else {
			let masked_bytes = bytes.iter().zip(mask.iter()).map(|(b, m)| b & m).collect();
			Ok(Self {
				bytes,
				mask,
				mask_type,
				masked_bytes,
			})
		}
	}

	/// Returns `true` if `pat` matches `data` at `offset`.
	pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
		let len = self.masked_bytes.len();
		if offset + len > data.len() {
			return false;
		}
		self
			.mask
			.iter()
			.zip(self.masked_bytes.iter())
			.enumerate()
			.all(|(i, (m, mb))| data[offset + i] & m == *mb)
	}

	// Shorthand for new with `MaskType::Byte`
	pub fn new_with_byte_mask(bytes: Vec<u8>, mask: Vec<u8>) -> InternalResult<Self> {
		Self::new(bytes, mask, MaskType::Byte)
	}

	// Shorthand for new with `MaskType::Nibble`
	pub fn new_with_nibble_mask(bytes: Vec<u8>, mask: Vec<u8>) -> InternalResult<Self> {
		Self::new(bytes, mask, MaskType::Nibble)
	}

	/// Helper function to convert an IDA Style Pattern (SigMaker) to the Byte Array with Mask
	/// representation and receive the prepared pattern
	pub fn from_ida_str(pattern: &str) -> InternalResult<Self> {
		let mut bytes: Vec<u8> = Vec::new();
		let mut mask: Vec<u8> = Vec::new();

		for p in pattern.split_whitespace() {
			if p == "?" || p == "??" {
				bytes.push(0);
				mask.push(0);
			} else {
				let b = u8::from_str_radix(p, 16).map_err(|o| Error::InvalidPattern {
					kind: PatternKind::Ida,
					repr: PatternRepr::BytesWithMask,
					hint: Some(Cow::Owned(o.to_string())),
				})?;
				bytes.push(b);
				mask.push(0xFF);
			}
		}

		Pattern::new_with_byte_mask(bytes, mask)
	}

	/// Helper function to convert an IDA Style Pattern (SigMaker) to the Byte Array with Mask
	/// representation and receive the prepared pattern, accepts Nibble patterns (48 4? ?5)
	pub fn from_ida_like_with_nibble(pattern: &str) -> InternalResult<Self> {
		let mut bytes: Vec<u8> = Vec::new();
		let mut mask: Vec<u8> = Vec::new();

		for p in pattern.split_whitespace() {
			let chars: Vec<char> = p.chars().collect();
			if chars.len() != 2 {
				return Err(Error::InvalidPattern {
					kind: PatternKind::Ida,
					repr: PatternRepr::BytesWithMask,
					hint: Some(Cow::Owned(format!("Invalid nibble token: {}", p))),
				});
			}

			let high = chars[0];
			let low = chars[1];

			let mut byte = 0u8;
			let mut m = 0u8;

			if high != '?' {
				let val = high.to_digit(16).ok_or_else(|| Error::InvalidPattern {
					kind: PatternKind::Ida,
					repr: PatternRepr::BytesWithMask,
					hint: Some(Cow::Owned(format!("Invalid hex char: {}", high))),
				})? as u8;

				byte |= val << 4;
				m |= 0xF0;
			}

			if low != '?' {
				let val = low.to_digit(16).ok_or_else(|| Error::InvalidPattern {
					kind: PatternKind::Ida,
					repr: PatternRepr::BytesWithMask,
					hint: Some(Cow::Owned(format!("Invalid hex char: {}", low))),
				})? as u8;

				byte |= val;
				m |= 0x0F;
			}

			bytes.push(byte);
			mask.push(m);
		}

		Pattern::new_with_nibble_mask(bytes, mask)
	}
}
