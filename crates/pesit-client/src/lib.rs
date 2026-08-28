//! PeSIT Wizard client library: the outbound transfer engine, its REST API and DTOs.
//!
//! Used by the unified `pesitwizard` node binary, which drives both the inbound listeners and this
//! outbound engine from one process.

#![allow(clippy::multiple_crate_versions)]

pub mod api;
pub mod engine;
pub mod model;
