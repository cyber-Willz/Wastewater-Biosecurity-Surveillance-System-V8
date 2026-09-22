//! Evaluate the shipped `ww_detection` engine (EWMA/Welford statistical
//! detector + spectral hypergraph network score) against real public
//! wastewater surveillance data: Public Health Scotland's national
//! SARS-CoV-2 wastewater monitoring programme (BioRDM/COVID-Wastewater-Scotland,
//! Scientific Data paper), May 2020 - Feb 2022, N1 gene RT-qPCR.
//!
//! Input: a pre-aggregated weekly CSV (site, health_board, week_start,
//! log10_conc, n_samples_in_week) — see the accompanying preprocessing
//! notes. Sites are grouped into pseudo-catchments by NHS Health Board
//! (an administrative proxy for shared sewer topology; the dataset does
//! not publish actual sewer connectivity, which the model's spectral
//! score is designed to consume, so this is a known approximation, and
//! the value of the spectral component here is weaker than for the
//! synthetic scenario where the true catchment topology is known).

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::File;

use ww_detection::{AnomalyDetector, SewageNetwork};

#[derive(Debug, Clone)]
struct Obs {
    week_start: String,
    log10_conc: f64,
}

// Widely-reported approximate UK/Scotland COVID-19 case-wave windows, used
// only as a coarse plausibility check (NOT derived from this dataset or
// exercise). Dates are inclusive [start, end).
const WAVE_WINDOWS: &[(&str, &str, &str)] = &[
    ("Alpha wave",   "2020-12-01", "2021-02-15"),
    ("Delta wave",   "2021-06-15", "2021-10-15"),
    ("Omicron wave", "2021-12-01", "2022-01-31"),
];

fn in_any_wave(date: &str) -> Option<&'static str> {
    WAVE_WINDOWS.iter().find(|(_, s, e)| date >= *s && date < *e).map(|(name, _, _)| *name)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = args.get(1).cloned().unwrap_or_else(|| "data/scotland_weekly.csv".to_string());
    let alpha_override: Option<f64> = args.get(3).and_then(|s| s.parse().ok());

    let file = File::open(&path).unwrap_or_else(|e| panic!("cannot open {path}: {e}"));
    let mut rdr = csv::Reader::from_reader(file);

    let mut by_site: BTreeMap<String, Vec<Obs>> = BTreeMap::new();
    let mut site_hb: HashMap<String, String> = HashMap::new();

    for rec in rdr.records() {
        let rec = rec.expect("csv row");
        let site = rec[0].to_string();
        let hb = rec[1].to_string();
        let week_start = rec[2].to_string();
        let log10_conc: f64 = rec[3].parse().expect("log10_conc");
        site_hb.insert(site.clone(), hb);
        by_site.entry(site).or_default().push(Obs { week_start, log10_conc });
    }
    for v in by_site.values_mut() {
        v.sort_by(|a, b| a.week_start.cmp(&b.week_start));
    }

    let sites: Vec<String> = by_site.keys().cloned().collect();
    eprintln!("# loaded {} sites from {}", sites.len(), path);
    for s in &sites {
        eprintln!("#   {:15} n_weeks={:4}  health_board={}", s, by_site[s].len(), site_hb[s]);
    }

    // Build catchments from shared Health Board membership (>=2 sites).
    let mut hb_members: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for s in &sites {
        hb_members.entry(site_hb[s].clone()).or_default().push(s.clone());
    }
    let catchments: Vec<(String, Vec<String>)> = hb_members
        .into_iter()
        .filter(|(_, members)| members.len() >= 2)
        .collect();
    eprintln!("# catchments with >=2 monitored sites (spectral pairing): {:?}",
        catchments.iter().map(|(k, v)| format!("{k}={v:?}")).collect::<Vec<_>>());

    let network = SewageNetwork::build(&catchments, &sites).expect("network build");
    let spread_thr = network.null_threshold(0.95, 20_000, 0x5eed_5eed);
    eprintln!("# spread_threshold(q95)={:.4}  fiedler={:.5}", spread_thr, network.fiedler_value());
    eprintln!("# alpha in use: {:.4} ({})", alpha_override.unwrap_or_else(ww_eval::sars_cov2::ewma_alpha),
        if alpha_override.is_some() { "override" } else { "shipped default for SARS-CoV-2" });

    // Union of all week_start dates across sites, in order: the shared "round" grid.
    let mut all_weeks: Vec<String> = by_site.values().flatten().map(|o| o.week_start.clone()).collect();
    all_weeks.sort();
    all_weeks.dedup();

    // Per-site cursor into its (sorted) observation list.
    let mut cursor: HashMap<String, usize> = sites.iter().map(|s| (s.clone(), 0usize)).collect();

    let mut detector = AnomalyDetector::new().with_spread_threshold(spread_thr);

    println!("site,week_start,log10_conc,z_score,spectral_score,severity,n_obs,in_known_wave");

    let trace_path = args.get(2).cloned().unwrap_or_else(|| "data/real_trace.csv".to_string());
    let mut trace = csv::Writer::from_path(&trace_path).expect("trace file");
    trace.write_record(["site", "week_start", "log10_conc", "z_before_ingest", "ewma_before", "n_obs_before"]).unwrap();

    let mut alerts_total = 0u64;
    let mut alerts_in_wave = 0u64;
    let mut alerts_out_of_wave = 0u64;
    let mut wave_hit: HashMap<&'static str, bool> = WAVE_WINDOWS.iter().map(|(n, _, _)| (*n, false)).collect();

    for week in &all_weeks {
        // Phase 1: which sites have an observation this week; build conc map.
        let mut concs: HashMap<String, f64> = HashMap::new();
        for s in &sites {
            let c = &cursor[s];
            let obs_list = &by_site[s];
            if *c < obs_list.len() && &obs_list[*c].week_start == week {
                concs.insert(s.clone(), obs_list[*c].log10_conc);
            }
        }
        if concs.is_empty() {
            continue;
        }

        // Phase 2: peek z-scores (pre-ingest) for the sites observed this round.
        let zmap: HashMap<String, f64> = concs
            .iter()
            .filter_map(|(s, c)| detector.peek_z(s, "SARS-CoV-2", *c).map(|z| (s.clone(), z)))
            .collect();
        let spectral = network.spectral_score_residual(&zmap);

        // Phase 3: ingest + detect for each observed site this round.
        for s in &sites {
            if let Some(&c) = concs.get(s) {
                let z_before = detector.peek_z(s, "SARS-CoV-2", c);
                let ewma_before = detector.baseline_mut().ewma(s, "SARS-CoV-2");
                let n_before = detector.baseline_mut().n_obs(s, "SARS-CoV-2");
                trace.write_record(&[
                    s.clone(), week.clone(), format!("{c:.3}"),
                    z_before.map(|z| format!("{z:.3}")).unwrap_or_default(),
                    ewma_before.map(|e| format!("{e:.3}")).unwrap_or_default(),
                    n_before.to_string(),
                ]).unwrap();

                if let Some(event) = detector.observe_analyte(
                    s, "SARS-CoV-2", c, spectral,
                    alpha_override.unwrap_or_else(ww_eval::sars_cov2::ewma_alpha), ww_eval::sars_cov2::Z_THRESHOLD,
                ) {
                    let wave = in_any_wave(week);
                    alerts_total += 1;
                    if let Some(w) = wave {
                        alerts_in_wave += 1;
                        wave_hit.insert(w, true);
                    } else {
                        alerts_out_of_wave += 1;
                    }
                    println!(
                        "{},{},{:.3},{:.3},{:.3},{},{},{}",
                        s, week, c, event.z_score, event.spectral_score,
                        event.severity.as_str(), event.n_obs,
                        wave.unwrap_or(""),
                    );
                }
                *cursor.get_mut(s).unwrap() += 1;
            }
        }
    }

    trace.flush().unwrap();
    eprintln!("# wrote full weekly trace to {trace_path}");
    eprintln!("# ---- summary ----");
    eprintln!("# total weekly rounds processed : {}", all_weeks.len());
    eprintln!("# total AMBER+ alerts           : {alerts_total}");
    eprintln!("# alerts inside a known wave    : {alerts_in_wave}  ({:.1}%)",
        100.0 * alerts_in_wave as f64 / alerts_total.max(1) as f64);
    eprintln!("# alerts outside known waves    : {alerts_out_of_wave}  ({:.1}%)",
        100.0 * alerts_out_of_wave as f64 / alerts_total.max(1) as f64);
    for (name, _, _) in WAVE_WINDOWS {
        eprintln!("# wave '{}': at least one site alerted = {}", name, wave_hit[name]);
    }
}
