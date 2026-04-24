use std::borrow::Cow;

use crate::pattern::types::{PatternKind, PatternRepr};

pub type InternalResult<T> = Result<T, Error>;

/// Represents the module errors
#[derive(Debug)]
pub enum Error {
	InvalidPattern {
		kind: PatternKind,
		repr: PatternRepr,
		hint: Option<Cow<'static, String>>,
	},
}
