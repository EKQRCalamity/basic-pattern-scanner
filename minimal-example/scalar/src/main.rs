use basic_pattern_scanner::{pattern::types::Pattern, scanner::{scalar::ScalarScanner, traits::PatternIterator}};

fn main() {
	// Scanner is a type without direct implementation but is implemented via the trait functions so
	// in case you do not want to save it and just use the Struct directly you can. Also this
	// basically gets resolved to `DefaultScanner` in current scope, so no need not to use
	// `DefaultScanner`.
	let scanner: ScalarScanner = ScalarScanner;

	let data: Vec<u8> = vec![/* Some data, maybe some ram dump or binary data, hopefully not just pasted here but loaded via RPM or file */];

	let data_bytes = data.as_slice();

	let full_pattern_str = "48 89 5C 24 ?? 48 83 EC ??";
	let nibble_pattern_str = "55 48 8? E?";

	let pattern = Pattern::from_ida_str(full_pattern_str).expect("Supplied wrong or invalid pattern!");

	let pattern_nibble = Pattern::from_ida_like_with_nibble(nibble_pattern_str).expect("Supplied wrong or invalid pattern!");

	// Iteratively scan all via Iterator implementation
	println!("Searching for {}...", full_pattern_str);
	for _match in scanner.scan_all(data_bytes, &pattern) {
		println!("{:#x}", _match.offset);
	}
	println!("Search finished!");

	println!("Searching with nibble {}...", nibble_pattern_str);
	for _match in scanner.scan_all(data_bytes, &pattern_nibble) {
		println!("{:#x}", _match.offset);
	}
	println!("Search finished!");

	// Lazily only scan for the first result
	if let Some(_match) = scanner.scan_all(data_bytes, &pattern).next() {
		println!("First offset: {:#x}", _match.offset);
	}

	// Get results as Vec<Match>
	let results = scanner.find_all(data_bytes, &pattern);

	println!("Number of offsets found: {}", results.len());
}
