## Basic PatternScanner
Basic Pattern scanner which supports Byte wise and Nibble wise scanning with raw byte/mask combinations as well as derivation from a ida/sigmaker pattern. Fully written in safe Rust.

With version 1.0.0 support for SIMD was added via the std::simd unstable nightly implementation branch. More SIMD implementations might be added, but will similarly be feature flag guarded. 

The `simd_std_unstable` feature flag requires Rust nightly to be built.

NOTE: THIS IS NOT AN IN-PROCESS MEMORY SCANNER, YOU WILL HAVE TO GET THE DATA OF THE BINARY OR PROCESS YOURSELF

## Usage

Examples can be found under [minimal-example](https://github.com/EKQRCalamity/basic_pattern_scanner/minimal_example/). These point to a directory path, so if it is removed from the folder structure you will have to change it to a release on [crates.io](https://crates.io).

If you checked out the examples, you will notice adoption of SIMD or vise versa Scalar is as easy as using a different `Scanner` implementing `PatternIterator`. The only hurdle for building with SIMD support is the nightly guard, but as long as you compile with `cargo +nightly` this should not be a problem. In my own setup I was able to see around a 1.3-2x increase in speed of search when using SIMD, this will MOST LIKELY differ on your own setup.

Another example of usage for this module can be found in my RPM/WPM project: [lime-rs](https://github.com/EKQRCalamity/lime-rs)
This is a project I try to keep up to date, but it's not meant as much of a public thing. So it's unlikely I will add a Readme for it.