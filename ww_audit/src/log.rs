//! Thread-safe, append-only audit log.
//!
//! Every auditable event in the system goes through [`AuditLog::record`].
//! The log lives entirely in memory during a session; call
//! [`AuditLog::export_ndjson`] to materialise the full trail as
//! newline-delimited JSON suitable for archival or regulatory submission.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::Utc;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

static AUDIT_CTR: AtomicU64 = AtomicU64::new(1);

fn next_audit_id() -> String {
    let n = AUDIT_CTR.fetch_add(1, Ordering::Relaxed);
    format!("aud_{n:06}")
}

// ── Action enum ──────────────────────────────────────────────────────────────

/// Every auditable event category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    SchemaRegistered,
    SiteAdded,
    SampleIngested,
    SignalDetected,
    AlertRaised,
    AlertConfirmed,
    AlertDismissed,
    AlertEscalated,
    ManualAnnotation,
    ReportGenerated,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditAction::SchemaRegistered => "SCHEMA_REGISTERED",
            AuditAction::SiteAdded        => "SITE_ADDED",
            AuditAction::SampleIngested   => "SAMPLE_INGESTED",
            AuditAction::SignalDetected   => "SIGNAL_DETECTED",
            AuditAction::AlertRaised      => "ALERT_RAISED",
            AuditAction::AlertConfirmed   => "ALERT_CONFIRMED",
            AuditAction::AlertDismissed   => "ALERT_DISMISSED",
            AuditAction::AlertEscalated   => "ALERT_ESCALATED",
            AuditAction::ManualAnnotation => "MANUAL_ANNOTATION",
            AuditAction::ReportGenerated  => "REPORT_GENERATED",
        }
    }
}

// ── Entry ────────────────────────────────────────────────────────────────────

/// One record in the append-only audit trail (immutable by API; not hash-chained or signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub audit_id:  String,
    /// ISO-8601 UTC timestamp with millisecond precision.
    pub timestamp: String,
    /// Actor that triggered the event (`"system"`, `"Dr. Martinez"`, …).
    pub actor:     String,
    /// Action category (uppercase snake-case string).
    pub action:    String,
    /// ID of the primary object this event relates to.
    pub target_id: String,
    /// Free-form detail string (human-readable or JSON fragment).
    pub details:   String,
}

// ── Log ──────────────────────────────────────────────────────────────────────

/// Thread-safe, append-only audit log.
///
/// Cloning an [`AuditLog`] handle gives a second handle to the *same*
/// underlying storage — all handles share the same entry list.  This is
/// intentional: pass `AuditLog` by value to subsystems without losing
/// visibility into their events.
#[derive(Clone, Default)]
pub struct AuditLog {
    entries: Arc<Mutex<Vec<AuditEntry>>>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one entry and return its generated `audit_id`.
    pub fn record(
        &self,
        actor:     &str,
        action:    AuditAction,
        target_id: &str,
        details:   impl Into<String>,
    ) -> String {
        let id = next_audit_id();
        self.entries.lock().push(AuditEntry {
            audit_id:  id.clone(),
            timestamp: Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
            actor:     actor.to_string(),
            action:    action.as_str().to_string(),
            target_id: target_id.to_string(),
            details:   details.into(),
        });
        id
    }

    /// All entries for a specific `target_id`, in insertion order.
    pub fn entries_for(&self, target_id: &str) -> Vec<AuditEntry> {
        self.entries
            .lock()
            .iter()
            .filter(|e| e.target_id == target_id)
            .cloned()
            .collect()
    }

    /// All entries, newest-first.
    pub fn recent(&self, n: usize) -> Vec<AuditEntry> {
        let guard = self.entries.lock();
        let start = guard.len().saturating_sub(n);
        guard[start..].iter().rev().cloned().collect()
    }

    /// Export as newline-delimited JSON (one JSON object per line).
    pub fn export_ndjson(&self) -> String {
        self.entries
            .lock()
            .iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }
}
