# Changelog

## v0.5 — Axum + PostgreSQL service (`ww_api`)

* **New crate `ww_api`:** Axum 0.7 REST service; PostgreSQL (tokio-postgres + deadpool) is the system of record for sites, catchments, observations, alerts, reviews and audit. Embedded, advisory-locked migrations; analyte catalog mirrored into the database.
* Detector state is derived: rebuilt from `observations` by replay at startup / after topology change / after any failed write. Detection path is the unchanged `ww_detection` engine (same peek-z → residual spectral score → observe sequence as `scotland_e2e`).
* Atomic round ingest (round + observations + alerts + audit in one transaction), strict per-analyte date ordering, multi-writer guard.
* Analyst review workflow with evidence chains; audit log append-only via database triggers; NDJSON export.
* Bearer-token auth on `/v1` (server refuses to start without a token unless `WW_ALLOW_ANONYMOUS=1`).
* `live_run_pg.sh`, `scotland_live` client and `ww_api/scripts/compare_alerts.py`: live PHS Scotland data through HTTP into PostgreSQL, diffed row-for-row against `scotland_e2e` (81/81 identical on the 2026-09-21 snapshot).
* PostgreSQL integration test (`WW_TEST_DATABASE_URL`).
* **Fix:** `ww_domain/src/analyte.rs` had a stray `];` after `ANALYTE_CATALOG` (crate did not compile).
* `Cargo.lock`: `idna_adapter` pinned to 1.2.0 to keep Rust 1.85 sufficient.
* Not changed: `ww_runner` / Belize simulation still use the in-memory `OntologyEngine`; the audit log is not hash-chained or signed.

## v0.4 — corrections + SHPINN (this archive)

Derived from the formal analysis in `docs/ww_biosec_theory.md`; measured effect in its Appendix C.

### Detection (`ww_detection`)
* **Fix:** the first observation of a `(site, analyte)` key was counted twice (`n = 2` after one sample). Warm-up is now exactly 7 prior observations.
* **Fix:** outbreaks inflated the variance they were scored against (self-masking). New `EwmaBaseline::ingest_robust` (winsorised EWMA, outlier-excluded Welford variance); `AnomalyDetector::observe_analyte` uses it with `clip_z = z_threshold`.
* **Fix:** `SewageNetwork` Rayleigh quotient normalised by `λ_max` (was `/2`, which only reached `[0, ½]`).
* **New:** `spectral_score_residual` (baseline-invariant network score on the mixing-scaled standardised residual), `residual_field`, `null_threshold` (deterministic empirical-null quantile), `laplacian()`, `sqrt_degrees()`.
* **New:** `AnomalyDetector::peek_z`, `with_spread_threshold` / `set_spread_threshold`, `DetectionSeverity::from_scores_with`.
* `spectral_score` (raw log₁₀ field) is kept for compatibility but documented as not baseline-invariant.
* 12 unit tests (exact Belize spectrum `{0, 1/21, 9/14, 1×5}`, score decomposition, warm-up count, robustness, severity table).

### Simulation (`ww_runner`)
* Network score computed from peeked z-scores (no raw-level input); upgrade threshold = null q95 of the score.
* Prints an SHPINN transport check per analyte category.

### New crate `ww_shpinn`
* Linear-feature physics-informed solver for `∂ₜc + v∂ₓc − D∂ₓₓc + kc = f` (exact least-squares, deterministic), data assimilation of measurements, analytic Gaussian reference, Theorem 7.1 constants (`kappa`, `stability_bound`).
* Hypergraph-regularised inverse source estimation (`prior_matrix`, `estimate_source`; Theorem 7.2 closed form).
* 7 unit tests, `examples/verify_forward.rs`.

### Docs
* README, doc comments (`lib.rs`, `analyte.rs`, `review.rs`, `log.rs`) corrected; `docs/ww_biosec_theory.md` added.

### Not changed
* The hypergraph is still built from catchments only; directed `site_flows_to` links are not used by the spectral model.
* `flow_liters` / `catchment_pop` are stored but do not enter detection.
* The audit log is an in-memory append-only vector (no hash chain / signatures).

### Measured effect on the shipped Belize scenario
| | v0.3 | v0.4 |
|---|---|---|
| alerts on pulse pairs / no-pulse pairs | 25 / 26 | 43 / 19 |
| injected pulses alerted (of 15) | 13 | 14 |
| spectral tier upgrades | 8 | 0 (calibrated threshold 0.966 never exceeded) |

## v0.3 — Explosive Precursor & Manufacturing Residue Surveillance

### New analyte category: `ExplosivePrecursor` (`[EXPX]`)

Seven analytes added to `ANALYTE_CATALOG` covering the primary wastewater-
detectable markers for energetic-material manufacture and post-blast
contamination:

| Analyte             | Marker        | Method     | k (d⁻¹) | z_thr |
|---------------------|---------------|------------|---------|-------|
| `RDX`               | RDX-LC-MSMS   | LC-MS/MS   | 0.02    | 3.5   |
| `HMX`               | HMX-LC-MSMS   | LC-MS/MS   | 0.01    | 3.5   |
| `TNT_aminoproducts` | 24ADNT-LC-MSMS| LC-MS/MS   | 0.08    | 3.5   |
| `PETN_penta`        | PENTA-LC-MSMS | LC-MS/MS   | 0.12    | 3.5   |
| `TATP_DHPP`         | DHPP-LC-MSMS  | LC-MS/MS   | 0.28    | 3.5   |
| `AN_nitrate_excess` | NO3-IC        | Ion Chrom. | 0.05    | 3.5   |
| `Perchlorate`       | ClO4-IC-MSMS  | IC-MS/MS   | 0.004   | 3.5   |

All use `z_threshold = 3.5` (AMBER unreachable; direct RED/CRITICAL entry),
consistent with the conservative false-positive policy for security referrals.

### Simulation scenario extensions

Three new outbreak pulses added to the Belize 15-day simulation:

* Days 10–13: RDX + HMX + TNT amino-products co-elevation at Belmopan
  Industrial Zone — simulated clandestine manufacturing cluster.
* Day 11: TATP-DHPP sharp spike at Belize City South — simulated
  improvised peroxide preparation event.
* Day 12: Perchlorate + AN excess at Orange Walk — simulated ANFO
  oxidiser sourcing.

### Analyst review escalation

New `ReviewOutcome::Escalate` arms added for all three explosive event types,
routing to:
- Belize National Security Council / Police Special Branch (RDX/HMX/TNT)
- Police Counter-Terrorism Unit (TATP)
- Pesticides Control Board + Police licence audit (AN/perchlorate)

### Theory document

`docs/ww_biosec_theory.md` §6 added covering:
- Compound selection and analytical methods
- Transport PDE kinetics (hydrolysis, biodegradation, sorption)
- Detection threshold rationale
- Co-elevation signature table for improved attribution
- Response escalation chain
- Limitations (no synthesis-route inference, matrix interference)

### Breaking changes

None. The `AnalyteCategory::from_str` fall-through default is
`InfectiousPathogen`, so old serialised data without `"explosive_precursor"`
round-trips correctly.
