//! In-memory detection state, rebuilt from PostgreSQL.
//!
//! The `AnomalyDetector` baselines are a deterministic function of the ordered
//! observation history, so they are *derived* state: on startup, after a
//! topology change, or after any failed write, [`Engine::rebuild`] replays
//! `observations` (per series, chronologically) into a fresh detector.
//! PostgreSQL stays the single source of truth.

use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;
use deadpool_postgres::Pool;
use ww_detection::{AnomalyDetector, SewageNetwork};
use ww_domain::analyte_by_name;

use crate::error::{ApiError, ApiResult};

/// Empirical-null quantile / sample count / seed for the spectral upgrade
/// threshold — identical to `ww_eval::scotland_e2e` so results are comparable.
pub const NULL_QUANTILE: f64 = 0.95;
pub const NULL_SAMPLES: usize = 20_000;
pub const NULL_SEED: u64 = 0x5eed_5eed;

pub struct Engine {
    pub network: Option<SewageNetwork>,
    pub detector: AnomalyDetector,
    pub spread_threshold: f64,
    /// Latest round date per analyte. EWMA is order-dependent, so rounds must
    /// arrive in strictly increasing date order per analyte.
    pub last_round: HashMap<String, NaiveDate>,
    pub sites: HashSet<String>,
    /// Set when in-memory state may have diverged from the database
    /// (failed write, concurrent writer). Cleared by `rebuild`.
    pub dirty: bool,
}

impl Engine {
    pub fn empty() -> Self {
        Self {
            network: None,
            detector: AnomalyDetector::new(),
            spread_threshold: 0.40,
            last_round: HashMap::new(),
            sites: HashSet::new(),
            dirty: true,
        }
    }

    /// Reload topology and replay all observations from the database.
    pub async fn rebuild(&mut self, pool: &Pool) -> ApiResult<()> {
        let conn = pool.get().await?;

        // `COLLATE "C"` = byte order = Rust's `BTreeMap<String,_>` order, so the
        // Laplacian's vertex order (and hence the numerics) matches the
        // reference `scotland_e2e` binary exactly.
        let sites: Vec<String> = conn
            .query(r#"SELECT site_id FROM monitoring_sites ORDER BY site_id COLLATE "C""#, &[])
            .await?
            .iter()
            .map(|r| r.get::<_, String>(0))
            .collect();

        let member_rows = conn
            .query(
                r#"SELECT catchment, site_id FROM catchment_members
                   ORDER BY catchment COLLATE "C", site_id COLLATE "C""#,
                &[],
            )
            .await?;
        let mut catchments: Vec<(String, Vec<String>)> = Vec::new();
        for r in &member_rows {
            let (c, s): (String, String) = (r.get(0), r.get(1));
            match catchments.last_mut() {
                Some((name, members)) if *name == c => members.push(s),
                _ => catchments.push((c, vec![s])),
            }
        }

        let n_catchments = catchments.len();
        let (network, spread) = if sites.len() >= 2 {
            let sites_c = sites.clone();
            let built = tokio::task::spawn_blocking(move || {
                let net = SewageNetwork::build(&catchments, &sites_c)
                    .map_err(|e| ApiError::Unprocessable(format!("cannot build network: {e}")))?;
                let thr = net.null_threshold(NULL_QUANTILE, NULL_SAMPLES, NULL_SEED);
                Ok::<_, ApiError>((net, thr))
            })
            .await
            .map_err(ApiError::internal)??;
            (Some(built.0), built.1)
        } else {
            (None, 0.40)
        };

        // Replay. The spectral score does not influence baseline updates, so 0.0
        // is passed; alerts for historical rounds already exist in the database.
        let mut detector = AnomalyDetector::new().with_spread_threshold(spread);
        let rows = conn
            .query(
                r#"SELECT analyte, site_id, log10_conc FROM observations
                   ORDER BY analyte COLLATE "C", observed_on, site_id COLLATE "C""#,
                &[],
            )
            .await?;
        let mut replayed = 0usize;
        for r in &rows {
            let (analyte, site, c): (String, String, f64) = (r.get(0), r.get(1), r.get(2));
            match analyte_by_name(&analyte) {
                Some(p) => {
                    let _ = detector.observe_analyte(
                        &site, &analyte, c, 0.0, p.ewma_alpha(), p.z_threshold,
                    );
                    replayed += 1;
                }
                None => tracing::warn!(%analyte, "observation for analyte missing from compiled catalog; skipped in replay"),
            }
        }

        let mut last_round = HashMap::new();
        for r in conn
            .query("SELECT analyte, max(observed_on) FROM rounds GROUP BY analyte", &[])
            .await?
        {
            last_round.insert(r.get::<_, String>(0), r.get::<_, NaiveDate>(1));
        }

        tracing::info!(
            sites = sites.len(), catchments = n_catchments, replayed,
            spread_threshold = spread, "engine rebuilt from database"
        );

        self.network = network;
        self.detector = detector;
        self.spread_threshold = spread;
        self.last_round = last_round;
        self.sites = sites.into_iter().collect();
        self.dirty = false;
        Ok(())
    }
}
