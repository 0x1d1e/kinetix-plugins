//! Fixture-driven fake host for compiled Kinetix plugin components.
//!
//! The plugins' native unit tests substitute `#[cfg(test)]` shims for the host
//! imports, so they never reach the production entrypoint. This crate builds a
//! plugin to a wasm component and runs it under wasmtime against a scripted
//! host (HTTP, storage, clock, credential), which exercises the real exports.
#![cfg(feature = "runtime")]

mod build;
mod host;

pub use build::build_component;
pub use host::{
    account_ref, val_to_json, Guest, HostState, HttpOutcome, HttpRequest, HttpResponse, Outcome,
    WireError,
};
pub use wasmtime::component::Val;
