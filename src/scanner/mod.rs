pub mod scalar;
pub mod traits;
pub mod types;

#[cfg(feature = "simd_std_unstable")]
pub mod simd_std;

#[cfg(feature = "simd_std_unstable")]
pub use simd_std::SimdScanner as DefaultScanner;

#[cfg(not(feature = "simd_std_unstable"))]
pub use scalar::ScalarScanner as DefaultScanner;


use crate::{pattern::types::Pattern, scanner::{traits::PatternIterator, types::{Match, MatchWithAddr}}};


pub fn scan_all(data: &[u8], pattern: &Pattern) -> Vec<Match> {
    DefaultScanner.find_all(data, pattern)
}

pub fn scan_all_with_base(data: &[u8], pattern: &Pattern, base: u64) -> Vec<MatchWithAddr> {
    DefaultScanner.find_all_with_base(data, pattern, base)
}

pub fn scan_all_iter<'a>(data: &'a [u8], pattern: &'a Pattern) -> impl Iterator<Item = Match> + 'a {
    DefaultScanner.scan_all(data, pattern)
}
