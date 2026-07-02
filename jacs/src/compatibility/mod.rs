//! Ecosystem compatibility surfaces (P2).
//!
//! Everything in this module is about making a JACS agent legible to
//! OUTSIDE ecosystems (W3C DID/VC, JOSE, A2A, AP2) without touching the
//! native signing contract: native `jacsSignature` stays PQ, and the
//! ES256 `ecosystem_signing` key is authorized per-export by the
//! PQ-root-signed binding in [`binding`].

pub mod binding;
