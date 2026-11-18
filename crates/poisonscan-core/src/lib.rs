//! poisonscan-core: detection engine for collection-to-LLM poisoning.
//!
//! This crate performs no I/O: it receives envelopes and rule definitions
//! as values, and returns findings.
#![forbid(unsafe_code)]

pub mod envelope;
pub mod normalize;
pub mod output;
pub mod rules;
pub mod scan;

pub use envelope::{Envelope, Source, Trust};
pub use rules::{Rule, RuleSet, Severity};
pub use scan::{Finding, Limits, ScanReport, Scanner, Verdict};

/// Version of the output event schema.
pub const OUTPUT_SCHEMA: &str = "poisonscan.finding/v1";
/// Version of the input envelope schema.
pub const ENVELOPE_SCHEMA: &str = "poisonscan.envelope/v1";
/// Version of the rule format this engine accepts.
pub const RULE_FORMAT: u32 = 1;
