# Live run report — ww_biosec v0.5 (Axum + PostgreSQL)

## What was done

1. **Environment fix (the only "error" found).** The sandbox's default Rust
   toolchain was 1.75, but this workspace requires Rust ≥ 1.85 (stated in
   `ww_api/README.md`; `sha2 0.11` even requires Cargo's `edition2024`
   support, which Cargo 1.75 cannot parse at all). Installed `rustc-1.91` /
   `cargo-1.91` via `apt` and pointed `PATH` at them. The workspace's own
   source code required **no changes** — every crate compiles cleanly with
   zero warnings-as-errors and zero errors on a correctly-versioned
   toolchain.

   One secondary environment issue: `rustdoc` was still resolving to the old
   1.75 binary after `cargo`/`rustc` were upgraded, which broke the
   `ontology_engine` doctest (`-Z unstable-options` / `check-cfg` mismatch
   between cargo 1.91 and rustdoc 1.75). Fixed by symlinking `rustdoc` to the
   1.91 build as well. Not a code bug — a toolchain-consistency issue in the
   build environment.

2. **Full workspace build** — `cargo build --workspace --release`: all 8
   workspace crates + 2 vendor crates (`ontology_engine`,
   `spectral_hypergraph`) build clean.

3. **Full test suite** — `cargo test --workspace --release`: **all green**.
   - `ontology_engine`: 17 integration tests + 1 doctest
   - `spectral_hypergraph`: 25 unit tests + 4 integration tests + 3 doctests
   - `ww_detection`: 13 tests (baseline, detector, spectral)
   - `ww_shpinn`: 7 tests (forward/inverse PDE solver)
   - `ww_api`: unit test + full `e2e.rs` integration test
     (`full_flow_persists_reviews_audits_and_replays`)
   - `scotland_e2e` date-handling: 4 tests

4. **Live end-to-end run** — installed PostgreSQL 16, created the `ww_biosec`
   database, and ran `live_run_pg.sh` against **live data**: the real Public
   Health Scotland national SARS-CoV-2 wastewater surveillance dataset,
   fetched fresh from
   `raw.githubusercontent.com/BioRDM/COVID-Wastewater-Scotland`.

## Live run result (2026-09-21 data snapshot)

```
Fetched dataset          : 10,317 lines (live)
Sites used / total       : 141 / 160 (min 8 weeks of history)
Weekly rounds processed  : 89
Reference (in-memory)    : 81 AMBER+ alerts
Live (HTTP -> Axum -> PG): 81 alerts — IDENTICAL to reference, same rows, same order

Restart-durability check : detector rebuilt from PostgreSQL replay
                            (sites=141 catchments=11 replayed=5458 obs)
Post-restart spike alert : RED, z=4.80, baseline n_obs=86 (warm, not cold) -> OK

Out-of-order ingestion   : correctly rejected (HTTP 409)
Analyst review workflow  : confirm + escalate both exercised successfully
Re-review of closed alert: correctly rejected (HTTP 409)
Audit-log immutability   : UPDATE / DELETE / TRUNCATE all rejected by DB trigger

Final DB state           : 141 sites, 11 catchments, 90 rounds,
                            5,459 observations, 82 alerts, 316 audit entries
```

This matches the result the project's own README documents for a live run
(141 sites, 89 rounds, 5,458 observations, 81 alerts, identical to
reference), confirming the shipped v0.5 system behaves exactly as designed
against real, freshly-fetched data — no code changes were needed.

## What's included in this archive vs. the original upload

- Full source tree, unchanged (no source-level bugs were found).
- `Cargo.lock`, generated during this build — pins dependency versions that
  are known-good with Rust ≥ 1.85 / 1.91 (matches the pinning the project
  README already calls out, e.g. `idna_adapter`).
- `live_run_out/` — the actual evidence from this run: the fetched live CSV,
  the reference alert set, the API/Postgres alert set (identical), the full
  per-site-per-week z-score trace, the audit-log NDJSON export, and the
  server log.
- `target/` build directory is **not** included (900MB+ of build artifacts,
  regenerable with `cargo build --release`).

## To reproduce

```bash
# Requires Rust >= 1.85, PostgreSQL, psql, curl, python3
createdb ww_biosec
export DATABASE_URL=postgres://<user>:<pw>@127.0.0.1/ww_biosec
./live_run_pg.sh
```
