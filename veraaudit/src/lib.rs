//! Veraaudit library - Audit log retrieval for Veracode
//!
//! This library provides functionality for retrieving and archiving Veracode audit logs.
pub mod audit;
pub mod cleanup;
pub mod cli;
pub mod credentials;
pub mod datetime;
pub mod error;
pub mod output;
pub mod service;
pub mod validation;
pub mod vault_client;

// Re-export commonly used types
pub use error::{AuditError, Result};
pub use service::ServiceConfig;
