use crate::pattern::types::Pattern;

pub struct Match {
	pub offset: usize,
}

pub struct MatchWithAddr {
	pub offset: usize,
	pub address: u64, // base + offset; u64 so it's valid on 32-bit hosts scanning 64-bit targets
}

/// Lazily yields every offset in `data` where `pat` matches.
/// Uses the first non-wildcard byte as an anchor to skip the full
/// comparison on most positions.
pub struct MatchIter<'a> {
	data: &'a [u8],
	pat: &'a Pattern,
	// First non-wildcard pattern byte used as a cheap pre-filter.
	anchor_idx: usize,
	anchor_masked: u8,
	anchor_mask: u8,
	pos: usize,
}

impl<'a> MatchIter<'a> {
	fn new(data: &'a [u8], pat: &'a Pattern) -> Self {
		// anchor_mask == 0 means all-wildcard pattern; the anchor check is skipped.
		let (anchor_idx, anchor_masked, anchor_mask) = pat
			.mask
			.iter()
			.zip(pat.masked_bytes.iter())
			.enumerate()
			.find(|(_, (m, _))| **m != 0)
			.map(|(i, (m, mb))| (i, *mb, *m))
			.unwrap_or((0, 0, 0));

		Self { data, pat, anchor_idx, anchor_masked, anchor_mask, pos: 0 }
	}
}

impl<'a> Iterator for MatchIter<'a> {
	type Item = Match;

	#[inline]
	fn next(&mut self) -> Option<Self::Item> {
		let pat_len = self.pat.masked_bytes.len();
		if pat_len == 0 {
			return None;
		}

		let data = self.data;
		let mask = self.pat.mask.as_slice();
		let mb = self.pat.masked_bytes.as_slice();
		let anchor_idx = self.anchor_idx;
		let anchor_masked = self.anchor_masked;
		let anchor_mask = self.anchor_mask;

		while self.pos + pat_len <= data.len() {
			let start = self.pos;
			self.pos += 1;

			if anchor_mask != 0
				&& (data[start + anchor_idx] & anchor_mask) != anchor_masked
			{
				continue;
			}

			if mask
				.iter()
				.zip(mb.iter())
				.enumerate()
				.all(|(i, (m, expected))| data[start + i] & m == *expected)
			{
				return Some(Match { offset: start });
			}
		}

		None
	}
}

pub struct MatchWithAddrIter<'a> {
	inner: MatchIter<'a>,
	base: u64,
}

impl<'a> Iterator for MatchWithAddrIter<'a> {
	type Item = MatchWithAddr;

	#[inline]
	fn next(&mut self) -> Option<Self::Item> {
		self.inner.next().map(|m| MatchWithAddr {
			offset: m.offset,
			address: self.base + m.offset as u64,
		})
	}
}

pub fn scan_all(data: &[u8], pat: &Pattern) -> Vec<Match> {
	scan_all_iter(data, pat).collect()
}

pub fn scan_all_with_base(data: &[u8], pat: &Pattern, base: u64) -> Vec<MatchWithAddr> {
	scan_all_with_base_iter(data, pat, base).collect()
}

pub fn scan_all_iter<'a>(data: &'a [u8], pat: &'a Pattern) -> MatchIter<'a> {
	MatchIter::new(data, pat)
}

pub fn scan_all_with_base_iter<'a>(
	data: &'a [u8],
	pat: &'a Pattern,
	base: u64,
) -> MatchWithAddrIter<'a> {
	MatchWithAddrIter { inner: MatchIter::new(data, pat), base }
}
