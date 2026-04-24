pub mod scalar;
pub mod traits;
pub mod types;

#[cfg(feature = "simd_std_unstable")]
pub mod simd_std;

#[cfg(feature = "simd_std_unstable")]
pub use simd_std::SimdScanner as DefaultScanner;

#[cfg(not(feature = "simd_std_unstable"))]
pub use scalar::ScalarScanner as DefaultScanner;
