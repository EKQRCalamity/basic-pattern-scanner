#![cfg_attr(feature = "simd_std_unstable", feature(portable_simd))]

pub mod error;
pub mod pattern;
pub mod scanner;

#[cfg(test)]
mod tests {
	use crate::pattern::types::Pattern;
	use crate::scanner::traits::PatternIterator;
use crate::scanner::{scalar, types::*};

	#[cfg(feature = "simd_std_unstable")]
	mod simd_tests {
		use super::*;
		use crate::scanner::simd_std::SimdScanner;
		use crate::scanner::traits::PatternIterator;

		fn offsets(matches: Vec<Match>) -> Vec<usize> {
			matches.into_iter().map(|m| m.offset).collect()
		}

		#[test]
		fn simd_single_match_at_start() {
			let data = &[0xDE, 0xAD, 0xBE, 0xEF, 0x00];
			let p = Pattern::from_ida_str("DE AD BE EF").unwrap();
			let scanner = SimdScanner;
			assert_eq!(offsets(scanner.find_all(data, &p)), &[0]);
		}

		#[test]
		fn simd_single_match_at_end() {
			let data = &[0x00, 0x00, 0xDE, 0xAD];
			let p = Pattern::from_ida_str("DE AD").unwrap();
			let scanner = SimdScanner;
			assert_eq!(offsets(scanner.find_all(data, &p)), &[2]);
		}

		#[test]
		fn simd_multiple_matches() {
			let data = &[0xAA, 0xBB, 0x00, 0xAA, 0xBB];
			let p = Pattern::from_ida_str("AA BB").unwrap();
			let scanner = SimdScanner;
			assert_eq!(offsets(scanner.find_all(data, &p)), &[0, 3]);
		}

		#[test]
		fn simd_no_match() {
			let data = &[0x11, 0x22, 0x33];
			let p = Pattern::from_ida_str("AA BB").unwrap();
			let scanner = SimdScanner;
			assert!(scanner.find_all(data, &p).is_empty());
		}

		#[test]
		fn simd_wildcard_matches_any_byte() {
			let data = &[0xAA, 0x00, 0xBB, 0xAA, 0xFF, 0xBB];
			let p = Pattern::from_ida_str("AA ?? BB").unwrap();
			let scanner = SimdScanner;
			assert_eq!(offsets(scanner.find_all(data, &p)), &[0, 3]);
		}

		#[test]
		fn simd_all_wildcard_pattern_matches_every_position() {
			let data = &[0x01, 0x02, 0x03];
			let p = Pattern::from_ida_str("?? ??").unwrap();
			let scanner = SimdScanner;
			assert_eq!(offsets(scanner.find_all(data, &p)), &[0, 1]);
		}

		#[test]
		fn simd_pattern_longer_than_data_no_match() {
			let data = &[0xAA, 0xBB];
			let p = Pattern::from_ida_str("AA BB CC DD").unwrap();
			let scanner = SimdScanner;
			assert!(scanner.find_all(data, &p).is_empty());
		}

		#[test]
		fn simd_matches_at_correct_positions() {
			let data = &[0x00, 0xAA, 0xBB, 0x00];
			let p = Pattern::from_ida_str("AA BB").unwrap();
			assert!(!p.matches_at(data, 0));
			assert!(p.matches_at(data, 1));
			assert!(!p.matches_at(data, 2));
		}

		#[test]
		fn simd_scan_with_base_address() {
			let data = &[0x00, 0xAA, 0xBB];
			let p = Pattern::from_ida_str("AA BB").unwrap();
			let base: u64 = 0x140000000;
			let scanner = SimdScanner;
			let results = scanner.find_all_with_base(data, &p, base);
			assert_eq!(results.len(), 1);
			assert_eq!(results[0].offset, 1);
			assert_eq!(results[0].address, base + 1);
		}

		#[test]
		fn simd_iter_stops_early() {
			let data = &[0xAA, 0x00, 0xAA, 0x00, 0xAA];
			let p = Pattern::from_ida_str("AA").unwrap();
			let scanner = SimdScanner;
			let first = scanner.scan_all(data, &p).next().unwrap();
			assert_eq!(first.offset, 0);
		}
	}

	fn offsets(matches: Vec<Match>) -> Vec<usize> {
		matches.into_iter().map(|m| m.offset).collect()
	}

	#[test]
	fn ida_str_exact() {
		let p = Pattern::from_ida_str("DE AD BE EF").unwrap();
		assert_eq!(p.bytes, &[0xDE, 0xAD, 0xBE, 0xEF]);
		assert_eq!(p.mask, &[0xFF, 0xFF, 0xFF, 0xFF]);
		assert_eq!(p.masked_bytes, &[0xDE, 0xAD, 0xBE, 0xEF]);
	}

	#[test]
	fn ida_str_with_wildcards() {
		let p = Pattern::from_ida_str("DE ?? BE EF").unwrap();
		assert_eq!(p.mask, &[0xFF, 0x00, 0xFF, 0xFF]);
		assert_eq!(p.masked_bytes, &[0xDE, 0x00, 0xBE, 0xEF]);
	}

	#[test]
	fn nibble_pattern_half_wildcards() {
		let p = Pattern::from_ida_like_with_nibble("?F").unwrap();
		assert_eq!(p.mask, &[0x0F]);
		assert_eq!(p.masked_bytes, &[0x0F]);
	}

	#[test]
	fn nibble_pattern_high_wildcard() {
		let p = Pattern::from_ida_like_with_nibble("A?").unwrap();
		assert_eq!(p.mask, &[0xF0]);
		assert_eq!(p.masked_bytes, &[0xA0]);
	}

	#[test]
	fn mask_shorter_than_bytes_is_error() {
		assert!(
			Pattern::new(
				vec![0xAA, 0xBB],
				vec![0xFF],
				crate::pattern::types::MaskType::Byte
			)
			.is_err()
		);
	}

	#[test]
	fn single_match_at_start() {
		let data = &[0xDE, 0xAD, 0xBE, 0xEF, 0x00];
		let p = Pattern::from_ida_str("DE AD BE EF").unwrap();
		assert_eq!(offsets(scalar::ScalarScanner.find_all(data, &p)), &[0]);
	}

	#[test]
	fn single_match_at_end() {
		let data = &[0x00, 0x00, 0xDE, 0xAD];
		let p = Pattern::from_ida_str("DE AD").unwrap();
		assert_eq!(offsets(scalar::ScalarScanner.find_all(data, &p)), &[2]);
	}

	#[test]
	fn multiple_matches() {
		let data = &[0xAA, 0xBB, 0x00, 0xAA, 0xBB];
		let p = Pattern::from_ida_str("AA BB").unwrap();
		assert_eq!(offsets(scalar::ScalarScanner.find_all(data, &p)), &[0, 3]);
	}

	#[test]
	fn no_match() {
		let data = &[0x11, 0x22, 0x33];
		let p = Pattern::from_ida_str("AA BB").unwrap();
		assert!(scalar::ScalarScanner.find_all(data, &p).is_empty());
	}

	#[test]
	fn wildcard_matches_any_byte() {
		let data = &[0xAA, 0x00, 0xBB, 0xAA, 0xFF, 0xBB];
		let p = Pattern::from_ida_str("AA ?? BB").unwrap();
		assert_eq!(offsets(scalar::ScalarScanner.find_all(data, &p)), &[0, 3]);
	}

	#[test]
	fn all_wildcard_pattern_matches_every_position() {
		let data = &[0x01, 0x02, 0x03];
		let p = Pattern::from_ida_str("?? ??").unwrap();
		assert_eq!(offsets(scalar::ScalarScanner.find_all(data, &p)), &[0, 1]);
	}

	#[test]
	fn pattern_longer_than_data_no_match() {
		let data = &[0xAA, 0xBB];
		let p = Pattern::from_ida_str("AA BB CC DD").unwrap();
		assert!(scalar::ScalarScanner.find_all(data, &p).is_empty());
	}

	#[test]
	fn matches_at_correct_positions() {
		let data = &[0x00, 0xAA, 0xBB, 0x00];
		let p = Pattern::from_ida_str("AA BB").unwrap();
		assert!(!p.matches_at(data, 0));
		assert!(p.matches_at(data, 1));
		assert!(!p.matches_at(data, 2)); // would run off the end
	}

	#[test]
	fn matches_at_oob_returns_false() {
		let data = &[0xAA];
		let p = Pattern::from_ida_str("AA BB").unwrap();
		assert!(!p.matches_at(data, 0));
		assert!(!p.matches_at(data, 1));
	}

	#[test]
	fn nibble_mask_scan() {
		let p = Pattern::from_ida_like_with_nibble("?F").unwrap();
		let data = &[0x0F, 0x1F, 0xAF, 0x10, 0xFF];
		assert_eq!(offsets(scalar::ScalarScanner.find_all(data, &p)), &[0, 1, 2, 4]);
	}

	#[test]
	fn nibble_mask_high_wildcard_scan() {
		let p = Pattern::from_ida_like_with_nibble("A?").unwrap();
		let data = &[0xA0, 0xAF, 0xBF, 0x0A];
		assert_eq!(offsets(scalar::ScalarScanner.find_all(data, &p)), &[0, 1]);
	}

	#[test]
	fn scan_with_base_address() {
		let data = &[0x00, 0xAA, 0xBB];
		let p = Pattern::from_ida_str("AA BB").unwrap();
		let base: u64 = 0x140000000;
		let results = scalar::ScalarScanner.find_all_with_base(data, &p, base);
		assert_eq!(results.len(), 1);
		assert_eq!(results[0].offset, 1);
		assert_eq!(results[0].address, base + 1);
	}

	#[test]
	fn iter_stops_early() {
		let data = &[0xAA, 0x00, 0xAA, 0x00, 0xAA];
		let p = Pattern::from_ida_str("AA").unwrap();
		let first = scalar::ScalarScanner.scan_all(data, &p).next().unwrap();
		assert_eq!(first.offset, 0);
	}

	#[test]
	fn iter_and_collect_agree() {
		let data: Vec<u8> = (0u8..=255).collect();
		let p = Pattern::from_ida_str("10 11 12").unwrap();
		let via_iter: Vec<usize> = scalar::ScalarScanner.scan_all(&data, &p).map(|m| m.offset).collect();
		let via_fn = offsets(scalar::ScalarScanner.find_all(&data, &p));
		assert_eq!(via_iter, via_fn);
	}

	// x86-64 prologue: mov [rsp+?],rbx / mov [rsp+?],rsi / push rdi / sub rsp,?
	// wildcard bytes are the variable displacement/immediate operands
	#[test]
	fn realistic_prologue_with_mid_wildcards() {
		#[rustfmt::skip]
		let data: &[u8] = &[
			0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
			0x48, 0x89, 0x5C, 0x24, 0x08,
			0x48, 0x89, 0x74, 0x24, 0x10,
			0x57,
			0x48, 0x83, 0xEC, 0x28,
			0xC3, 0x90, 0x90, 0x90,
		];

		let p = Pattern::from_ida_str("48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ??").unwrap();

		let matches = scalar::ScalarScanner.find_all(data, &p);
		assert_eq!(matches.len(), 1);
		assert_eq!(matches[0].offset, 12);
		assert!(p.matches_at(data, 12));
		assert!(!p.matches_at(data, 0));
	}

	#[test]
	fn nibble_overlapping_matches_and_rejection() {
		let data: &[u8] = &[0xAB, 0xAB, 0xAB, 0xAB, 0xAB];

		let p_match = Pattern::from_ida_like_with_nibble("AB ?B").unwrap();
		assert_eq!(offsets(scalar::ScalarScanner.find_all(data, &p_match)), &[0, 1, 2, 3]);

		let p_no_match = Pattern::from_ida_like_with_nibble("AB ?0").unwrap();
		assert!(scalar::ScalarScanner.find_all(data, &p_no_match).is_empty());
	}
}
