//! `ww_api` — Axum REST service backed by PostgreSQL for the ww_biosec
//! wastewater surveillance pipeline.
//!
//! * PostgreSQL is the system of record (sites, catchments, observations,
//!   alerts, review decisions, append-only audit log).
//! * The `ww_detection` engine (EWMA baselines + spectral hypergraph score) runs
//!   in-process; its state is derived from the database by replay
//!   (see [`engine`]), so a restart loses nothing.
//! * Every `/v1` route requires `Authorization: Bearer <token>`.

pub mod audit;
pub mod db;
pub mod engine;
pub mod error;
pub mod handlers;
pub mod network;
pub mod rounds;
pub mod webhook;

use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::header,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use deadpool_postgres::Pool;
use tokio::sync::Mutex;

use crate::engine::Engine;
use crate::error::{ApiError, ApiResult};
use crate::webhook::{WebhookConfig, WebhookDispatcher};

pub struct AppState {
    pub pool: Pool,
    pub engine: Mutex<Engine>,
    /// `None` disables auth (explicit opt-in in `main`; used by tests).
    pub token: Option<String>,
    /// Outbound webhook dispatcher for n8n integration.
    /// Fires are async fire-and-forget; failures are logged, never fatal.
    pub hooks: WebhookDispatcher,
}

impl AppState {
    /// Migrate, seed the analyte catalog, and build the detector from the
    /// database contents.
    pub async fn init(pool: Pool, token: Option<String>) -> ApiResult<Arc<Self>> {
        db::migrate(&pool).await?;
        db::seed_analytes(&pool).await?;
        let mut engine = Engine::empty();
        engine.rebuild(&pool).await?;
        let hooks = {
            let cfg = WebhookConfig::from_env();
            if cfg.base_url.is_some() {
                tracing::info!(base_url = cfg.base_url.as_deref().unwrap(), "n8n webhooks enabled");
            } else {
                tracing::info!("n8n webhooks disabled (WW_N8N_BASE_URL not set)");
            }
            WebhookDispatcher::new(cfg)
        };
        Ok(Arc::new(Self { pool, engine: Mutex::new(engine), token, hooks }))
    }

    /// z-score of a prospective value against the live baseline (diagnostics/tests).
    pub async fn peek_z(&self, site: &str, analyte: &str, log10_conc: f64) -> Option<f64> {
        self.engine.lock().await.detector.peek_z(site, analyte, log10_conc)
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/analytes", get(handlers::analytes))
        .route("/network", get(network::get_network).put(network::put_network))
        .route("/rounds", post(rounds::post_round))
        .route("/observations", get(handlers::list_observations))
        .route("/alerts", get(handlers::list_alerts))
        .route("/alerts/:id", get(handlers::get_alert))
        .route("/alerts/:id/evidence", get(handlers::alert_evidence))
        .route("/alerts/:id/review", post(handlers::review_alert))
        .route("/summary", get(handlers::summary))
        .route("/audit", get(handlers::list_audit))
        .route("/audit/export", get(handlers::export_audit))
        .layer(middleware::from_fn_with_state(state.clone(), require_token));

    Router::new()
        .route("/healthz", get(handlers::healthz))
        .nest("/v1", api)
        .layer(DefaultBodyLimit::max(8 * 1024 * 1024))
        .with_state(state)
}

async fn require_token(
    State(st): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if let Some(expected) = &st.token {
        let presented = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if !constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
            return Err(ApiError::Unauthorized);
        }
    }
    Ok(next.run(req).await)
}

/// Length-independent-ish constant-time comparison (no early exit on content).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn token_comparison() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret2"));
        assert!(!constant_time_eq(b"", b"secret"));
        assert!(constant_time_eq(b"", b""));
    }
}
