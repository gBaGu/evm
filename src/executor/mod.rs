//! # EVM executors
//!
//! Executors are structs that hook gasometer and the EVM core together. It
//! also handles the call stacks in EVM.

mod stack;
pub mod traces;

pub use self::stack::{
	MemoryStackState, Precompile, PrecompileOutput, PrecompileResult, StackExecutor, StackExitKind,
	StackState, StackSubstateMetadata,
};
