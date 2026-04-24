pub struct Match {
	pub offset: usize,
}

pub struct MatchWithAddr {
	pub offset: usize,
	pub address: u64, // base + offset; u64 so it's valid on 32-bit hosts scanning 64-bit targets
}
