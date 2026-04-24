use crate::{
	pattern::types::Pattern,
	scanner::types::{Match, MatchWithAddr},
};

/// Trait for base implementation for different types of scanners.
pub trait PatternIterator {
	fn scan_all<'a>(
		&self,
		data: &'a [u8],
		pattern: &'a Pattern,
	) -> Box<dyn Iterator<Item = Match> + 'a>;

	/// This is a convienience function which calculates the offset + base and gives back both
	fn scan_all_with_base<'a>(
		&self,
		data: &'a [u8],
		pattern: &'a Pattern,
		base: u64,
	) -> Box<dyn Iterator<Item = MatchWithAddr> + 'a> {
		Box::new(
			self
				.scan_all(data, pattern)
				.map(move |_match| MatchWithAddr {
					offset: _match.offset,
					address: base + _match.offset as u64,
				}),
		)
	}

	/// This is a convienience function which collects the full iterator from `scan_all` into an
	/// `Vec<MatchWithAddr>`
	fn find_all(&self, data: &[u8], pattern: &Pattern) -> Vec<Match> {
		self.scan_all(data, pattern).collect()
	}

	/// This is a convienience function which collects the full iterator from `scan_all_with_base` into an
	/// `Vec<MatchWithAddr>`
	fn find_all_with_base(&self, data: &[u8], pattern: &Pattern, base: u64) -> Vec<MatchWithAddr> {
		self.scan_all_with_base(data, pattern, base).collect()
	}
}
