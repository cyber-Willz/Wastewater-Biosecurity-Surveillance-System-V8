//! Audit-trail helper. Action strings mirror `ww_audit::AuditAction::as_str`
//! so NDJSON exports stay compatible with the in-memory log's format.

use tokio_postgres::Transaction;

use crate::error::ApiResult;

pub const NETWORK_UPDATED: &str = "NETWORK_UPDATED";
pub const SITE_ADDED: &str = "SITE_ADDED";
pub const ROUND_INGESTED: &str = "SAMPLE_INGESTED";
pub const ALERT_RAISED: &str = "ALERT_RAISED";
pub const ALERT_CONFIRMED: &str = "ALERT_CONFIRMED";
pub const ALERT_DISMISSED: &str = "ALERT_DISMISSED";
pub const ALERT_ESCALATED: &str = "ALERT_ESCALATED";

pub async fn record(
    tx: &Transaction<'_>,
    actor: &str,
    action: &str,
    target_id: &str,
    details: &str,
) -> ApiResult<()> {
    tx.execute(
        "INSERT INTO audit_log (actor, action, target_id, details) VALUES ($1,$2,$3,$4)",
        &[&actor, &action, &target_id, &details],
    )
    .await?;
    Ok(())
}
