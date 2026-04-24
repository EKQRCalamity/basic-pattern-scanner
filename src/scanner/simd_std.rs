#![cfg(feature = "simd_std_unstable")]

use std::simd::prelude::*;

use crate::pattern::types::Pattern;
use crate::scanner::scalar::MatchIter as ScalarIter;
use crate::scanner::traits::PatternIterator;
use crate::scanner::types::Match;

/// 16 is usually fine, if you are sure your hardware supports 32 bit lanes
const LANES: usize = 16;
type U8xN = Simd<u8, LANES>;

pub struct SimdScanner;

impl PatternIterator for SimdScanner {
	fn scan_all<'a>(
		&self,
		data: &'a [u8],
		pattern: &'a Pattern,
	) -> Box<dyn Iterator<Item = Match> + 'a> {
		Box::new(SimdMatchIter::new(data, pattern))
	}
}

pub struct SimdMatchIter<'a> {
	data: &'a [u8],
	pattern: &'a Pattern,
	anchor_idx: usize,
	anchor_mask: u8,
	anchor_masked: u8,
	simd_pos: usize,
	candidates: [usize; LANES],
	candidates_len: usize,
	candidates_pos: usize,
	tail: Option<ScalarIter<'a>>,
}

impl<'a> SimdMatchIter<'a> {
	fn new(data: &'a [u8], pattern: &'a Pattern) -> Self {
		let (anchor_idx, anchor_masked, anchor_mask) = pattern
			.mask
			.iter()
			.zip(pattern.masked_bytes.iter())
			.enumerate()
			.find(|(_, (mask, _))| **mask != 0)
			.map(|(idx, (mask, masked_bool))| (idx, *masked_bool, *mask))
			.unwrap_or((0, 0, 0));

		Self {
			data,
			pattern,
			anchor_idx,
			anchor_mask,
			anchor_masked,
			simd_pos: 0,
			candidates: [0usize; LANES],
			candidates_len: 0,
			candidates_pos: 0,
			tail: None,
		}
	}

	/// Returns `false` when no more SIMD chunks are available
	fn fill_candidates(&mut self) -> bool {
		let pattern_length = self.pattern.masked_bytes.len();

		if pattern_length == 0 {
			return false;
		}

		let anchor_end = self.simd_pos + self.anchor_idx + LANES;
		let pattern_end = self.simd_pos + LANES - 1 + pattern_length;
		let required = anchor_end.max(pattern_end);

		if required > self.data.len() {
			return false;
		}

		self.candidates_pos = 0;
		self.candidates_len = 0;

		if self.anchor_mask == 0 {
			// Full wildcard
			for lane in 0..LANES {
				self.candidates[self.candidates_len] = self.simd_pos + lane;
				self.candidates_len += 1;
			}
		} else {
			let needle = U8xN::splat(self.anchor_masked);
			let mask_v = U8xN::splat(self.anchor_mask);

			let window = U8xN::from_slice(
				&self.data[self.simd_pos + self.anchor_idx..self.simd_pos + self.anchor_idx + LANES],
			);

			let hits = (window & mask_v).simd_eq(needle);

			if hits.any() {
				let bits = hits.to_bitmask();
				for lane in 0..LANES {
					if bits & (1u64 << lane) != 0 {
						self.candidates[self.candidates_len] = self.simd_pos + lane;
						self.candidates_len += 1;
					}
				}
			}
		}

		self.simd_pos += LANES;

		true
	}
}

impl<'a> Iterator for SimdMatchIter<'a> {
	type Item = Match;

	#[inline]
	fn next(&mut self) -> Option<Self::Item> {
		loop {
			if let Some(ref mut tail) = self.tail {
				return tail.next();
			}

			while self.candidates_pos < self.candidates_len {
				let start = self.candidates[self.candidates_pos];
				self.candidates_pos += 1;

				if self.pattern.matches_at(self.data, start) {
					return Some(Match { offset: start });
				}
			}

			if !self.fill_candidates() {
				let base_offset = self.simd_pos;

				self.tail = Some(ScalarIter::new_at(self.data, self.pattern, base_offset));
			}
		}
	}
}
