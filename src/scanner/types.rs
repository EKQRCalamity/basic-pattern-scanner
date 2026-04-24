/// Struct which holds the offset of the matched region
pub struct Match {
	pub offset: usize,
}

/// Struct which holds the offset as well as the address calculated from base + offset of the
/// matched region
pub struct MatchWithAddr {
	pub offset: usize,
	pub address: u64, // base + offset; u64 so it's valid on 32-bit hosts scanning 64-bit targets
}
