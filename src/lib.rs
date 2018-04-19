//! Rust implementation of the [SPONGENT][sp] cryptographic functions.
//!
//! Primarily based on this [C++ implementation][cp]
//!
//! [cp]: https://github.com/sancus-pma/sancus-compiler/blob/master/src/crypto/spongent.cpp
//! [sp]: https://eprint.iacr.org/2011/697.pdf

#![no_std]

extern crate constant_time_eq;

mod spongent;
pub use spongent::*;
