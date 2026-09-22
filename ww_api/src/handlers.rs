//! Read endpoints, evidence chains, and the analyst review workflow.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, NaiveDate, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio_postgres::Row;

use crate::audit;
use crate::error::{ApiError, ApiResult};
use crate::AppState;

fn clamp_limit(l: Option<i64>) -> i64 {
    l.unwrap_or(100).clamp(1, 1000)
}

pub async fn healthz(State(st): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let conn = st.pool.get().await?;
    conn.query_one("SELECT 1", &[]).await?;
    Ok(Json(json!({ "status": "ok" })))
}

pub async fn analytes(State(st): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let conn = st.pool.get().await?;
    let rows = conn
        .query(
            "SELECT name, category, target_marker, method, decay_rate_k, z_threshold, ewma_alpha
             FROM analytes ORDER BY category, name",
            &[],
        )
        .await?;
    Ok(Json(json!(rows
        .iter()
        .map(|r| json!({
            "name": r.get::<_, String>(0), "category": r.get::<_, String>(1),
            "target_marker": r.get::<_, String>(2), "method": r.get::<_, String>(3),
            "decay_rate_k": r.get::<_, f64>(4), "z_threshold": r.get::<_, f64>(5),
            "ewma_alpha": r.get::<_, f64>(6),
        }))
        .collect::<Vec<_>>())))
}

// ── observations ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ObsQuery {
    site_id: Option<String>,
    analyte: Option<String>,
    from: Option<NaiveDate>,
    to: Option<NaiveDate>,
    limit: Option<i64>,
    offset: Option<i64>,
}

pub async fn list_observations(
    State(st): State<Arc<AppState>>,
    Query(q): Query<ObsQuery>,
) -> ApiResult<Json<Value>> {
    let conn = st.pool.get().await?;
    let rows = conn
        .query(
            "SELECT obs_id, round_id, site_id, analyte, observed_on, log10_conc, n_samples, source
             FROM observations
             WHERE ($1::text IS NULL OR site_id = $1)
               AND ($2::text IS NULL OR analyte = $2)
               AND ($3::date IS NULL OR observed_on >= $3)
               AND ($4::date IS NULL OR observed_on <= $4)
             ORDER BY observed_on, site_id COLLATE \"C\"
             LIMIT $5 OFFSET $6",
            &[&q.site_id, &q.analyte, &q.from, &q.to, &clamp_limit(q.limit), &q.offset.unwrap_or(0).max(0)],
        )
        .await?;
    Ok(Json(json!(rows
        .iter()
        .map(|r| json!({
            "obs_id": r.get::<_, i64>("obs_id"), "round_id": r.get::<_, i64>("round_id"),
            "site_id": r.get::<_, String>("site_id"), "analyte": r.get::<_, String>("analyte"),
            "observed_on": r.get::<_, NaiveDate>("observed_on"),
            "log10_conc": r.get::<_, f64>("log10_conc"), "n_samples": r.get::<_, i32>("n_samples"),
            "source": r.get::<_, String>("source"),
        }))
        .collect::<Vec<_>>())))
}

// ── alerts ───────────────────────────────────────────────────────────────────

const ALERT_COLS: &str = "alert_id, obs_id, round_id, site_id, analyte, observed_on, log10_conc,
    ewma, z_score, spectral_score, severity, n_obs, alpha, status, analyst_notes,
    reviewed_by, reviewed_at, created_at";

fn alert_json(r: &Row) -> Value {
    json!({
        "alert_id": r.get::<_, i64>("alert_id"), "obs_id": r.get::<_, i64>("obs_id"),
        "round_id": r.get::<_, i64>("round_id"), "site_id": r.get::<_, String>("site_id"),
        "analyte": r.get::<_, String>("analyte"),
        "observed_on": r.get::<_, NaiveDate>("observed_on"),
        "log10_conc": r.get::<_, f64>("log10_conc"), "ewma": r.get::<_, f64>("ewma"),
        "z_score": r.get::<_, f64>("z_score"), "spectral_score": r.get::<_, f64>("spectral_score"),
        "severity": r.get::<_, String>("severity"), "n_obs": r.get::<_, i32>("n_obs"),
        "alpha": r.get::<_, f64>("alpha"), "status": r.get::<_, String>("status"),
        "analyst_notes": r.get::<_, String>("analyst_notes"),
        "reviewed_by": r.get::<_, Option<String>>("reviewed_by"),
        "reviewed_at": r.get::<_, Option<DateTime<Utc>>>("reviewed_at"),
        "created_at": r.get::<_, DateTime<Utc>>("created_at"),
    })
}

#[derive(Debug, Deserialize)]
pub struct AlertQuery {
    status: Option<String>,
    severity: Option<String>,
    analyte: Option<String>,
    site_id: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

/// Alerts, critical-first (matches `ReviewSession::pending_alerts` ordering),
/// then chronological.
pub async fn list_alerts(
    State(st): State<Arc<AppState>>,
    Query(q): Query<AlertQuery>,
) -> ApiResult<Json<Value>> {
    let conn = st.pool.get().await?;
    let sql = format!(
        "SELECT {ALERT_COLS} FROM alerts
         WHERE ($1::text IS NULL OR status = $1)
           AND ($2::text IS NULL OR severity = $2)
           AND ($3::text IS NULL OR analyte = $3)
           AND ($4::text IS NULL OR site_id = $4)
         ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'RED' THEN 1 ELSE 2 END,
                  observed_on, site_id COLLATE \"C\", alert_id
         LIMIT $5 OFFSET $6"
    );
    let rows = conn
        .query(
            &sql,
            &[&q.status, &q.severity, &q.analyte, &q.site_id, &clamp_limit(q.limit), &q.offset.unwrap_or(0).max(0)],
        )
        .await?;
    Ok(Json(json!(rows.iter().map(alert_json).collect::<Vec<_>>())))
}

pub async fn get_alert(State(st): State<Arc<AppState>>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let conn = st.pool.get().await?;
    let row = conn
        .query_opt(&format!("SELECT {ALERT_COLS} FROM alerts WHERE alert_id = $1"), &[&id])
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("alert {id} not found")))?;
    Ok(Json(alert_json(&row)))
}

fn audit_json(r: &Row) -> Value {
    json!({
        "audit_id": r.get::<_, i64>("audit_id").to_string(),
        "timestamp": r.get::<_, DateTime<Utc>>("ts").to_rfc3339_opts(SecondsFormat::Millis, true),
        "actor": r.get::<_, String>("actor"), "action": r.get::<_, String>("action"),
        "target_id": r.get::<_, String>("target_id"), "details": r.get::<_, String>("details"),
    })
}

/// Provenance chain: alert → observation → site → catchments, the other sites
/// that reported in the same round, and the audit trail (alert + round).
pub async fn alert_evidence(
    State(st): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let conn = st.pool.get().await?;
    let alert = conn
        .query_opt(&format!("SELECT {ALERT_COLS} FROM alerts WHERE alert_id = $1"), &[&id])
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("alert {id} not found")))?;
    let (obs_id, round_id, site_id): (i64, i64, String) =
        (alert.get("obs_id"), alert.get("round_id"), alert.get("site_id"));

    let obs = conn
        .query_one(
            "SELECT obs_id, observed_on, log10_conc, n_samples, source, ingested_at
             FROM observations WHERE obs_id = $1",
            &[&obs_id],
        )
        .await?;
    let site = conn
        .query_one("SELECT site_id, name, region FROM monitoring_sites WHERE site_id = $1", &[&site_id])
        .await?;
    let catchments: Vec<String> = conn
        .query(r#"SELECT catchment FROM catchment_members WHERE site_id = $1 ORDER BY catchment COLLATE "C""#, &[&site_id])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let round = conn
        .query_one(
            "SELECT round_id, analyte, observed_on, n_observations, n_warm, spectral_score,
                    spread_threshold, n_alerts FROM rounds WHERE round_id = $1",
            &[&round_id],
        )
        .await?;
    let peers = conn
        .query(
            r#"SELECT o.site_id, o.log10_conc, (a.alert_id IS NOT NULL) AS alerted
               FROM observations o LEFT JOIN alerts a ON a.obs_id = o.obs_id
               WHERE o.round_id = $1 AND o.site_id <> $2
               ORDER BY o.site_id COLLATE "C""#,
            &[&round_id, &site_id],
        )
        .await?;
    let trail = conn
        .query(
            "SELECT audit_id, ts, actor, action, target_id, details FROM audit_log
             WHERE target_id = ANY($1) ORDER BY audit_id",
            &[&vec![format!("alert:{id}"), format!("round:{round_id}")]],
        )
        .await?;

    Ok(Json(json!({
        "alert": alert_json(&alert),
        "observation": {
            "obs_id": obs.get::<_, i64>("obs_id"), "observed_on": obs.get::<_, NaiveDate>("observed_on"),
            "log10_conc": obs.get::<_, f64>("log10_conc"), "n_samples": obs.get::<_, i32>("n_samples"),
            "source": obs.get::<_, String>("source"), "ingested_at": obs.get::<_, DateTime<Utc>>("ingested_at"),
        },
        "site": {
            "site_id": site.get::<_, String>("site_id"), "name": site.get::<_, Option<String>>("name"),
            "region": site.get::<_, Option<String>>("region"), "catchments": catchments,
        },
        "round": {
            "round_id": round.get::<_, i64>("round_id"), "analyte": round.get::<_, String>("analyte"),
            "observed_on": round.get::<_, NaiveDate>("observed_on"),
            "n_observations": round.get::<_, i32>("n_observations"), "n_warm": round.get::<_, i32>("n_warm"),
            "spectral_score": round.get::<_, f64>("spectral_score"),
            "spread_threshold": round.get::<_, f64>("spread_threshold"), "n_alerts": round.get::<_, i32>("n_alerts"),
        },
        "same_round_sites": peers.iter().map(|r| json!({
            "site_id": r.get::<_, String>(0), "log10_conc": r.get::<_, f64>(1), "alerted": r.get::<_, bool>(2),
        })).collect::<Vec<_>>(),
        "audit_trail": trail.iter().map(audit_json).collect::<Vec<_>>(),
    })))
}

// ── review workflow ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Confirm,
    Dismiss,
    Escalate,
}

#[derive(Debug, Deserialize)]
pub struct ReviewRequest {
    pub analyst: String,
    pub outcome: Outcome,
    /// Notes (confirm/escalate) or reason (dismiss).
    #[serde(default)]
    pub notes: String,
    /// Required for `escalate`.
    #[serde(default)]
    pub to_team: Option<String>,
}

/// Confirm / dismiss / escalate an alert. Status change and audit record are
/// written in one transaction. Only OPEN or ESCALATED alerts can be reviewed.
pub async fn review_alert(
    State(st): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(req): Json<ReviewRequest>,
) -> ApiResult<Json<Value>> {
    if req.analyst.trim().is_empty() {
        return Err(ApiError::Unprocessable("analyst is required".into()));
    }
    let (status, action, notes) = match &req.outcome {
        Outcome::Confirm => ("CONFIRMED", audit::ALERT_CONFIRMED, req.notes.clone()),
        Outcome::Dismiss => {
            if req.notes.trim().is_empty() {
                return Err(ApiError::Unprocessable("dismiss requires a reason in `notes`".into()));
            }
            ("DISMISSED", audit::ALERT_DISMISSED, req.notes.clone())
        }
        Outcome::Escalate => {
            let team = req
                .to_team
                .as_deref()
                .filter(|t| !t.trim().is_empty())
                .ok_or_else(|| ApiError::Unprocessable("escalate requires `to_team`".into()))?;
            ("ESCALATED", audit::ALERT_ESCALATED, format!("[→ {team}] {}", req.notes))
        }
    };

    let mut conn = st.pool.get().await?;
    let tx = conn.transaction().await?;
    let current: String = tx
        .query_opt("SELECT status FROM alerts WHERE alert_id = $1 FOR UPDATE", &[&id])
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("alert {id} not found")))?
        .get(0);
    if current != "OPEN" && current != "ESCALATED" {
        return Err(ApiError::Conflict(format!("alert {id} is already {current}")));
    }
    tx.execute(
        "UPDATE alerts SET status = $2, analyst_notes = $3, reviewed_by = $4, reviewed_at = now()
         WHERE alert_id = $1",
        &[&id, &status, &notes, &req.analyst],
    )
    .await?;
    audit::record(&tx, &req.analyst, action, &format!("alert:{id}"), &notes).await?;
    let row = tx
        .query_one(&format!("SELECT {ALERT_COLS} FROM alerts WHERE alert_id = $1"), &[&id])
        .await?;
    tx.commit().await?;
    let updated = alert_json(&row);
    // Fire n8n webhook after commit (fire-and-forget; failures are logged only).
    st.hooks.fire_alert_reviewed(&updated, status, &req.analyst);
    Ok(Json(updated))
}

// ── summary & audit ──────────────────────────────────────────────────────────

pub async fn summary(State(st): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let conn = st.pool.get().await?;
    let counts = conn
        .query_one(
            "SELECT (SELECT count(*) FROM monitoring_sites), (SELECT count(*) FROM observations),
                    (SELECT count(*) FROM rounds), (SELECT count(*) FROM alerts),
                    (SELECT count(*) FROM audit_log)",
            &[],
        )
        .await?;
    let by_sev = conn
        .query(
            "SELECT severity, status, count(*) FROM alerts GROUP BY 1,2 ORDER BY 1,2",
            &[],
        )
        .await?;
    let by_analyte = conn
        .query(
            "SELECT analyte, count(*), min(observed_on), max(observed_on), sum(n_alerts)::bigint
             FROM rounds GROUP BY analyte ORDER BY analyte",
            &[],
        )
        .await?;
    Ok(Json(json!({
        "sites": counts.get::<_, i64>(0), "observations": counts.get::<_, i64>(1),
        "rounds": counts.get::<_, i64>(2), "alerts": counts.get::<_, i64>(3),
        "audit_entries": counts.get::<_, i64>(4),
        "alerts_by_severity_status": by_sev.iter().map(|r| json!({
            "severity": r.get::<_, String>(0), "status": r.get::<_, String>(1), "count": r.get::<_, i64>(2),
        })).collect::<Vec<_>>(),
        "rounds_by_analyte": by_analyte.iter().map(|r| json!({
            "analyte": r.get::<_, String>(0), "rounds": r.get::<_, i64>(1),
            "first": r.get::<_, NaiveDate>(2), "last": r.get::<_, NaiveDate>(3),
            "alerts": r.get::<_, i64>(4),
        })).collect::<Vec<_>>(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    target_id: Option<String>,
    action: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

pub async fn list_audit(
    State(st): State<Arc<AppState>>,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Value>> {
    let conn = st.pool.get().await?;
    let rows = conn
        .query(
            "SELECT audit_id, ts, actor, action, target_id, details FROM audit_log
             WHERE ($1::text IS NULL OR target_id = $1) AND ($2::text IS NULL OR action = $2)
             ORDER BY audit_id DESC LIMIT $3 OFFSET $4",
            &[&q.target_id, &q.action, &clamp_limit(q.limit), &q.offset.unwrap_or(0).max(0)],
        )
        .await?;
    Ok(Json(json!(rows.iter().map(audit_json).collect::<Vec<_>>())))
}

/// Full audit trail as NDJSON, oldest first — same field layout as
/// `ww_audit::AuditEntry` / `AuditLog::export_ndjson`.
pub async fn export_audit(State(st): State<Arc<AppState>>) -> ApiResult<Response> {
    let conn = st.pool.get().await?;
    let rows = conn
        .query(
            "SELECT audit_id, ts, actor, action, target_id, details FROM audit_log ORDER BY audit_id",
            &[],
        )
        .await?;
    // NDJSON: one object per line, each line (including the last) newline-terminated.
    let mut body = String::new();
    for r in &rows {
        body.push_str(&audit_json(r).to_string());
        body.push('\n');
    }
    let mut resp = body.into_response();
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/x-ndjson"));
    Ok(resp)
}
