//! Bound the work each Harvest contract does in one call on an update.
//!
//! A Freenet node stops a contract call after 5 s of wall clock
//! (`RuntimeConfig::max_execution_seconds`). An update to a contract at its
//! caps that costs most of that fails on a busy peer, and every peer hosting
//! the contract pays it for every update (harvest#226). Native unit tests
//! cannot see this: they run several times faster than the contract WASM on
//! the node and have no limit at all.
//!
//! This runs the COMMITTED contract WASM under wasmtime with fuel metering,
//! drives each contract through the calls a node makes for one UPDATE
//! against a state at its caps, and fails if any single call consumes more
//! than [`BUDGET_FUEL`]. Fuel counts WASM instructions executed, so the
//! result is identical on every machine and every run: this is not a timing
//! test and cannot flake. See README.md for how the budget was calibrated
//! against wall-clock time.
//!
//! Usage:
//!   harvest-contract-budget [--wasm-dir DIR] [--calibrate [REPS]]
//!                           [--only CONTRACT] [--case SUBSTRING]

mod cases;
mod host;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use freenet_stdlib::prelude::{
    bincode, ContractError, RelatedContracts, StateDelta, StateSummary, UpdateData,
    UpdateModification, ValidateResult,
};

use cases::{Case, Kind, Update};
use host::Contract;

/// The most fuel one contract call may consume.
///
/// Roughly ONE SECOND of contract work on the reference machine (nova), a
/// fifth of the node's 5 s per-call limit, at the SLOWEST rate measured
/// there with the node's engine and memory layout: 2.28 billion fuel/s, the
/// reputation contract's full-state merge, which moves about 80 MB of state
/// through memory. Most calls ran at 3.4 to 5.3 billion fuel/s, so for them
/// this is about 0.4 to 0.65 s. The margin is for everything fuel does not
/// see: a slower CPU than the reference, a node under load (the limit is
/// wall clock), host time on the node, and the bulk-memory undercount
/// (wasmtime charges one unit for a `memory.copy` of any length).
/// Calibration, and how to redo it: README.md.
const BUDGET_FUEL: u64 = 2_200_000_000;

/// The seconds of work [`BUDGET_FUEL`] stands for, for the report only.
const BUDGET_SECONDS: f64 = 1.0;

struct Measured {
    contract: &'static str,
    /// From `Kind::gates`: an over-budget call of a report-only contract is
    /// printed as a warning and does not fail the run.
    gating: bool,
    tracked_by: &'static str,
    case: String,
    call: &'static str,
    fuel: Option<u64>,
    /// Why the call, or the update it is part of, failed: the fuel ceiling,
    /// a trap (out of the node's 256 MiB memory, a panic), or, for a
    /// report-only contract, a refusal or an unusable answer. Each is a
    /// failure: on a node the update fails the same way.
    trap: Option<String>,
    host_calls: u64,
    /// `--calibrate` only: the best unmetered, node-like wall time of the
    /// call, and the part of it spent in the host.
    timing: Option<(Duration, Duration)>,
}

impl Measured {
    fn over(&self) -> bool {
        self.trap.is_some() || over_budget(self.fuel)
    }

    /// Over, on a contract that gates: this fails the run.
    fn fails_run(&self) -> bool {
        self.over() && self.gating
    }

    /// Over, on a report-only contract: this is a warning.
    fn warns(&self) -> bool {
        self.over() && !self.gating
    }
}

/// The calls that fail the run.
fn gating_failures(measured: &[Measured]) -> Vec<&Measured> {
    measured.iter().filter(|m| m.fails_run()).collect()
}

/// The process exit code for a run's outcome: 0 when every gating call is
/// within budget, 1 when one is not, 2 when the harness could not drive the
/// contracts.
fn exit_code(outcome: &Result<bool>) -> u8 {
    match outcome {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(_) => 2,
    }
}

fn over_budget(fuel: Option<u64>) -> bool {
    fuel.is_none_or(|f| f > BUDGET_FUEL)
}

struct Runner {
    contracts: Vec<(Kind, Contract)>,
    calibrate_reps: usize,
    measured: Vec<Measured>,
}

/// The encoded arguments of one entry-point call, as the node writes them.
struct Call<'a> {
    entry: &'static str,
    label: &'static str,
    args: Vec<&'a [u8]>,
}

impl Runner {
    fn contract(&self, kind: Kind) -> &Contract {
        &self
            .contracts
            .iter()
            .find(|(k, _)| *k == kind)
            .expect("every kind is loaded")
            .1
    }

    /// Run one call metered (and timed, under `--calibrate`), record it, and
    /// return the bincode result, or `None` if the call trapped or ran past
    /// the fuel ceiling. Both are recorded as failures and end the case: the
    /// node's update stops there too.
    fn measure(&mut self, case: &Case, call: Call<'_>) -> Result<Option<Vec<u8>>> {
        let contract = self.contract(case.kind);
        let timing = if self.calibrate_reps > 0 {
            let mut best: Option<(Duration, Duration)> = None;
            for _ in 0..self.calibrate_reps {
                // A call that traps has no time worth reporting.
                let Ok(t) = contract.time_unmetered(call.entry, &call.args) else {
                    break;
                };
                if best.is_none_or(|b| t.0 < b.0) {
                    best = Some(t);
                }
            }
            best
        } else {
            None
        };
        let outcome = contract.call(call.entry, &call.args)?;
        let m = Measured {
            contract: case.kind.name(),
            gating: case.kind.gates(),
            tracked_by: case.kind.tracked_by(),
            case: case.name.clone(),
            call: call.label,
            fuel: outcome.fuel,
            trap: outcome.result.as_ref().err().cloned(),
            host_calls: outcome.host_calls,
            timing,
        };
        print_line(&m);
        self.measured.push(m);
        Ok(outcome.result.ok())
    }

    /// Run `entry` without recording it: a call made only to get an input
    /// for a measured one.
    fn quiet(&self, kind: Kind, entry: &str, args: &[&[u8]]) -> Result<Vec<u8>> {
        self.contract(kind)
            .call(entry, args)?
            .result
            .map_err(|e| anyhow!("{entry} (unmeasured): {e}"))
    }

    /// The update of `case` cannot go on: a refusal, an invalid state, an
    /// update that changed nothing. On a gating contract the fixture or the
    /// contract is wrong in a way the budget cannot judge, so the run stops
    /// (exit 2). On a report-only contract it is recorded against the last
    /// call measured, with its reason, as a warning, and the run goes on.
    fn problem(&mut self, case: &Case, e: anyhow::Error) -> Result<()> {
        if case.kind.gates() {
            return Err(e);
        }
        let reason = format!("{e:#}");
        println!("{:>12}report-only, not judged further: {reason}", "");
        if let Some(m) = self.measured.last_mut() {
            m.trap.get_or_insert(reason);
        }
        Ok(())
    }

    /// What a node runs for one UPDATE of `case`'s contract.
    ///
    /// freenet-core's `upsert` path (`executor_impl.rs`): a full incoming
    /// state is validated first (`validate_state`), then merged
    /// (`attempt_state_update`, the WASM `update_state`), and the merged
    /// state is validated (`fetch_related_for_validation`). A changed state
    /// is committed and fanned out: the node summarizes it and sends each
    /// co-host the delta against that co-host's summary (`summarize_state`,
    /// `get_state_delta`). A merge of full states is re-run with the merged
    /// state as the held one, sampled 1 in 32, to check idempotency
    /// (`maybe_probe_idempotency`). Each of these is a separate guest call
    /// under the node's 5 s limit, so each is measured on its own.
    fn run_case(&mut self, case: &Case) -> Result<()> {
        let related = bincode::serialize(&RelatedContracts::default())?;
        let params = case.parameters.as_slice();
        let held = case.held.as_slice();
        let update = match &case.update {
            Update::Delta(d) | Update::RefusedDelta(d) => {
                UpdateData::Delta(StateDelta::from(d.clone()))
            }
            Update::State(s) => UpdateData::State(s.clone().into()),
        };
        let updates = bincode::serialize(&vec![update])?;

        if let Update::RefusedDelta(_) = &case.update {
            let Some(r) = self.measure(
                case,
                Call {
                    entry: "update_state",
                    label: "update_state (must refuse)",
                    args: vec![params, held, &updates],
                },
            )?
            else {
                return Ok(());
            };
            let r: Result<UpdateModification<'_>, ContractError> = bincode::deserialize(&r)?;
            if r.is_ok() {
                let e = anyhow!(
                    "{} / {}: update_state accepted a delta it must refuse",
                    case.kind.name(),
                    case.name
                );
                return self.problem(case, e);
            }
            return Ok(());
        }

        if let Update::State(incoming) = &case.update {
            let Some(r) = self.measure(
                case,
                Call {
                    entry: "validate_state",
                    label: "validate_state (incoming state)",
                    args: vec![params, incoming, &related],
                },
            )?
            else {
                return Ok(());
            };
            if let Err(e) = expect_valid(case, "validate_state (incoming state)", &r) {
                return self.problem(case, e);
            }
        }

        let Some(r) = self.measure(
            case,
            Call {
                entry: "update_state",
                label: "update_state",
                args: vec![params, held, &updates],
            },
        )?
        else {
            return Ok(());
        };
        let merged = match new_state(case, &r) {
            Ok(m) => m,
            Err(e) => return self.problem(case, e),
        };
        if merged == case.held {
            let e = anyhow!(
                "{} / {}: the update changed nothing, so the node would stop after \
                 update_state and the fixture is not exercising a real update",
                case.kind.name(),
                case.name
            );
            return self.problem(case, e);
        }

        let Some(r) = self.measure(
            case,
            Call {
                entry: "validate_state",
                label: "validate_state (merged state)",
                args: vec![params, &merged, &related],
            },
        )?
        else {
            return Ok(());
        };
        if let Err(e) = expect_valid(case, "validate_state (merged state)", &r) {
            return self.problem(case, e);
        }

        let Some(r) = self.measure(
            case,
            Call {
                entry: "summarize_state",
                label: "summarize_state (merged state)",
                args: vec![params, &merged],
            },
        )?
        else {
            return Ok(());
        };
        let summary: Result<StateSummary<'_>, ContractError> = bincode::deserialize(&r)?;
        if let Err(e) = summary {
            let e = anyhow!("{} / {}: summarize_state: {e}", case.kind.name(), case.name);
            return self.problem(case, e);
        }

        // The co-host the fan-out sends to holds the state from before the
        // update: its summary is what it advertised.
        let old_summary = self.quiet(case.kind, "summarize_state", &[params, held])?;
        let old_summary: Result<StateSummary<'_>, ContractError> =
            bincode::deserialize(&old_summary)?;
        let old_summary = old_summary
            .map_err(|e| anyhow!("summarize_state (held, unmeasured): {e}"))?
            .into_bytes();
        let Some(r) = self.measure(
            case,
            Call {
                entry: "get_state_delta",
                label: "get_state_delta (to a co-host holding the old state)",
                args: vec![params, &merged, &old_summary],
            },
        )?
        else {
            return Ok(());
        };
        if let Err(e) = nonempty_delta(case, "a co-host holding the old state", &r) {
            return self.problem(case, e);
        }

        // A new subscriber has no state: its summary is zero bytes, and the
        // delta it is sent is the whole state, re-encoded.
        let Some(r) = self.measure(
            case,
            Call {
                entry: "get_state_delta",
                label: "get_state_delta (to a new subscriber, empty summary)",
                args: vec![params, &merged, &[]],
            },
        )?
        else {
            return Ok(());
        };
        if let Err(e) = nonempty_delta(case, "a new subscriber", &r) {
            return self.problem(case, e);
        }

        if matches!(case.update, Update::State(_)) {
            let Some(r) = self.measure(
                case,
                Call {
                    entry: "update_state",
                    label: "update_state (idempotency probe, 1 in 32)",
                    args: vec![params, &merged, &updates],
                },
            )?
            else {
                return Ok(());
            };
            if let Err(e) = new_state(case, &r) {
                return self.problem(case, e);
            }
        }
        Ok(())
    }
}

/// A `get_state_delta` answer that is a non-empty delta.
fn nonempty_delta(case: &Case, to: &str, bytes: &[u8]) -> Result<()> {
    let delta: Result<StateDelta<'_>, ContractError> = bincode::deserialize(bytes)?;
    let delta = delta.map_err(|e| {
        anyhow!(
            "{} / {}: get_state_delta to {to}: {e}",
            case.kind.name(),
            case.name
        )
    })?;
    if delta.as_ref().is_empty() {
        bail!(
            "{} / {}: get_state_delta found nothing to send to {to}, though the state changed",
            case.kind.name(),
            case.name
        );
    }
    Ok(())
}

fn expect_valid(case: &Case, what: &str, bytes: &[u8]) -> Result<()> {
    let r: Result<ValidateResult, ContractError> = bincode::deserialize(bytes)?;
    match r {
        Ok(ValidateResult::Valid) => Ok(()),
        other => bail!(
            "{} / {}: {what} answered {other:?}: the fixture is not a state the contract \
             accepts, so its cost proves nothing",
            case.kind.name(),
            case.name
        ),
    }
}

fn new_state(case: &Case, bytes: &[u8]) -> Result<Vec<u8>> {
    let r: Result<UpdateModification<'_>, ContractError> = bincode::deserialize(bytes)?;
    match r {
        Ok(UpdateModification {
            new_state: Some(s), ..
        }) => Ok(s.as_ref().to_vec()),
        other => bail!(
            "{} / {}: update_state answered {other:?}: a refused update is cheap and would \
             pass the budget for the wrong reason",
            case.kind.name(),
            case.name
        ),
    }
}

fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn percent(fuel: Option<u64>) -> String {
    fuel.map_or("-".into(), |f| {
        format!("{:.1}%", f as f64 * 100.0 / BUDGET_FUEL as f64)
    })
}

/// `pass`, `FAIL` (fails the run), or `WARN` (over, report-only).
fn verdict(m: &Measured) -> &'static str {
    if m.fails_run() {
        "FAIL"
    } else if m.warns() {
        "WARN"
    } else {
        "pass"
    }
}

fn print_line(m: &Measured) {
    let fuel = m.fuel.map_or("past the ceiling".into(), group);
    println!(
        "{:<10} {:<44} {:<52} {fuel:>17} / {} {:>7} {}",
        m.contract,
        m.case,
        m.call,
        group(BUDGET_FUEL),
        percent(m.fuel),
        verdict(m)
    );
    if let Some(trap) = &m.trap {
        // The trap and the top of the guest backtrace: enough to say where.
        for line in trap.lines().take(12) {
            println!("{:>12}{line}", "");
        }
    }
}

/// BLAKE3, as `scripts/check-code-hashes.sh` prints it, so a reader can
/// match the measured file to the committed one.
fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn default_wasm_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../ui/public/contracts")
}

fn run() -> Result<bool> {
    let mut args = std::env::args().skip(1);
    let mut wasm_dir = default_wasm_dir();
    let mut calibrate_reps = 0usize;
    let mut only: Option<String> = None;
    let mut case_filter: Option<String> = None;
    let mut write_ratchet = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--only" => only = Some(args.next().ok_or_else(|| anyhow!("--only CONTRACT"))?),
            "--case" => case_filter = Some(args.next().ok_or_else(|| anyhow!("--case SUBSTRING"))?),
            "--wasm-dir" => wasm_dir = args.next().ok_or_else(|| anyhow!("--wasm-dir DIR"))?.into(),
            "--calibrate" => calibrate_reps = 3,
            "--write-ratchet" => write_ratchet = true,
            n if calibrate_reps > 0 && n.parse::<usize>().is_ok() => {
                calibrate_reps = n.parse().unwrap()
            }
            other => {
                bail!(
                    "unknown argument {other}; usage: [--wasm-dir DIR] [--calibrate [REPS]] \
                     [--only CONTRACT] [--case SUBSTRING] [--write-ratchet]"
                )
            }
        }
    }

    let mut hashes = Vec::new();
    let mut contracts = Vec::new();
    for kind in Kind::ALL {
        let path = wasm_dir.join(kind.file());
        let wasm = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let hash = blake3_hex(&wasm);
        println!(
            "{:<10} {} ({} bytes, blake3 {hash})",
            kind.name(),
            path.display(),
            wasm.len()
        );
        hashes.push((kind, hash));
        contracts.push((kind, Contract::new(&wasm, calibrate_reps > 0)?));
    }
    println!(
        "budget:    {} fuel per call (~{BUDGET_SECONDS} s of work on the reference machine; \
         the node's limit is 5 s)",
        group(BUDGET_FUEL)
    );
    println!();

    let mut runner = Runner {
        contracts,
        calibrate_reps,
        measured: Vec::new(),
    };
    let mut failure = None;
    if let Some(only) = &only {
        if !Kind::ALL.iter().any(|k| k.name() == only) {
            bail!("--only {only}: no such contract");
        }
    }
    let selected = cases::all()?.into_iter().filter(|c| {
        only.as_deref().is_none_or(|o| c.kind.name() == o)
            && case_filter.as_deref().is_none_or(|f| c.name.contains(f))
    });
    for case in selected {
        if let Err(e) = runner.run_case(&case) {
            failure = Some(e);
            break;
        }
    }

    let ok = report(&runner.measured, &hashes, failure.as_ref())?;
    let ratchet_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(RATCHET_FILE);
    let ratchet_ok = if write_ratchet {
        std::fs::write(&ratchet_path, write_ratchet_file(&runner.measured))
            .with_context(|| format!("write {}", ratchet_path.display()))?;
        println!("wrote {}", ratchet_path.display());
        true
    } else {
        let recorded = std::fs::read_to_string(&ratchet_path)
            .with_context(|| format!("read {}", ratchet_path.display()))?;
        let broken = ratchet_failures(&runner.measured, &parse_ratchet(&recorded)?);
        for why in &broken {
            eprintln!("::error::ratchet: {why}");
        }
        broken.is_empty()
    };
    let ok = ok && ratchet_ok;
    match failure {
        // A call past the fuel ceiling is already an over-budget result;
        // anything else that stopped the run is a harness failure.
        Some(e) => Err(e.context("the scenario did not complete")),
        None => Ok(ok),
    }
}

/// Print the summary, write the GitHub step summary, and say whether every
/// call fit the budget.
fn report(
    measured: &[Measured],
    hashes: &[(Kind, String)],
    failure: Option<&anyhow::Error>,
) -> Result<bool> {
    let over = gating_failures(measured);
    let reported: Vec<&Measured> = measured.iter().filter(|m| m.warns()).collect();

    let mut md = String::new();
    writeln!(md, "## Harvest contracts: work per call on an update").ok();
    writeln!(md).ok();
    let artifacts: Vec<String> = hashes
        .iter()
        .map(|(k, h)| format!("{} `{}`", k.name(), &h[..16.min(h.len())]))
        .collect();
    writeln!(
        md,
        "Contracts {}; budget **{}** fuel per call (about {BUDGET_SECONDS} s of work; the \
         node stops a call at 5 s). Fuel is deterministic: these numbers are the same on every \
         run and every machine.",
        artifacts.join(", "),
        group(BUDGET_FUEL)
    )
    .ok();
    writeln!(md).ok();
    writeln!(md, "| contract | case | call | fuel | of budget | |").ok();
    writeln!(md, "|---|---|---|---:|---:|---|").ok();
    for m in measured {
        writeln!(
            md,
            "| {} | {} | {} | {} | {} | {} |",
            m.contract,
            m.case,
            m.call,
            m.fuel.map_or("past the ceiling".into(), group),
            percent(m.fuel),
            match (&m.trap, m.over(), m.gating) {
                (Some(t), _, false) => format!(
                    ":warning: report-only ({}): {}",
                    m.tracked_by,
                    t.lines().next().unwrap_or(t)
                ),
                (None, true, false) => format!(":warning: over, report-only ({})", m.tracked_by),
                (Some(t), _, true) => format!(":x: **{}**", t.lines().next().unwrap_or(t)),
                (None, true, true) => ":x: **over budget**".into(),
                (None, false, _) => String::new(),
            }
        )
        .ok();
    }

    if measured.iter().any(|m| m.timing.is_some()) {
        println!();
        println!(
            "calibration (best unmetered run, node-like engine: Cranelift OptLevel::None, \
             epoch interruption, the node's memory layout)"
        );
        println!(
            "{:<10} {:<44} {:<52} {:>17} {:>9} {:>8} {:>8} {:>15}",
            "contract", "case", "call", "fuel", "wall ms", "host ms", "refills", "fuel/s (guest)"
        );
        for m in measured.iter().filter(|m| m.timing.is_some()) {
            let (wall, host) = m.timing.unwrap();
            let guest = wall.saturating_sub(host).as_secs_f64();
            let fuel = m.fuel.unwrap_or(0) as f64;
            println!(
                "{:<10} {:<44} {:<52} {:>17} {:>9.1} {:>8.1} {:>8} {:>15}",
                m.contract,
                m.case,
                m.call,
                m.fuel.map_or("-".into(), group),
                wall.as_secs_f64() * 1e3,
                host.as_secs_f64() * 1e3,
                m.host_calls,
                if guest > 0.0 {
                    group((fuel / guest) as u64)
                } else {
                    "-".into()
                },
            );
        }
    }

    writeln!(md).ok();
    if let Some(e) = failure {
        writeln!(md, ":x: The scenario stopped early: `{e:#}`").ok();
        if !over.is_empty() {
            writeln!(md).ok();
            writeln!(md, "Gating calls already over budget before it stopped:").ok();
            for m in &over {
                writeln!(md, "* {} / {} / {}", m.contract, m.case, m.call).ok();
            }
        }
    } else if over.is_empty() {
        writeln!(md, "Every gating call is within budget.").ok();
    } else {
        writeln!(
            md,
            ":x: {} call(s) over budget. On a node such a call risks running past the 5 s \
             wall-clock limit on a busy peer, and every peer hosting the contract pays it for \
             every update. See `tests/contract-budget/README.md`.",
            over.len()
        )
        .ok();
    }
    if !reported.is_empty() {
        writeln!(
            md,
            ":warning: {} report-only call(s) over budget; they do not fail the run (see \
             `Kind::gates`).",
            reported.len()
        )
        .ok();
    }
    // The unit tests call `report` too; they must not write into the CI
    // step summary of the run that hosts them.
    if let (false, Ok(path)) = (cfg!(test), std::env::var("GITHUB_STEP_SUMMARY")) {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)?
            .write_all(md.as_bytes())?;
    }

    println!();
    for m in &reported {
        match &m.trap {
            Some(t) => eprintln!(
                "::warning::{} / {} / {}: {} (report-only until {})",
                m.contract,
                m.case,
                m.call,
                t.lines().next().unwrap_or(t),
                m.tracked_by
            ),
            None => eprintln!(
                "::warning::{} / {} / {}: over budget, report-only until {}",
                m.contract, m.case, m.call, m.tracked_by
            ),
        }
    }
    if over.is_empty() {
        println!("every gating call is within {} fuel", group(BUDGET_FUEL));
    } else {
        for m in &over {
            match &m.trap {
                Some(trap) => eprintln!(
                    "::error::{} / {} / {}: {}",
                    m.contract,
                    m.case,
                    m.call,
                    trap.lines().next().unwrap_or(trap)
                ),
                None => eprintln!(
                    "::error::{} / {} / {}: {} fuel exceeds the per-call budget of {}",
                    m.contract,
                    m.case,
                    m.call,
                    m.fuel.map_or("past the ceiling".into(), group),
                    group(BUDGET_FUEL)
                ),
            }
        }
    }
    Ok(over.is_empty())
}

/// The figures the report-only calls are held to (`--write-ratchet` writes
/// them), next to this crate's manifest.
const RATCHET_FILE: &str = "ratchet.tsv";

/// How far above its recorded figure a report-only call may go before the
/// run fails: report-only means over the budget is a warning, not that
/// growing is free (the overseer, step 2: the store's calls stay over the
/// budget until harvest#230, and must not silently get worse meanwhile).
const RATCHET_PERCENT: u64 = 110;

/// One line per report-only call measured: contract, case, call, fuel.
fn write_ratchet_file(measured: &[Measured]) -> String {
    let mut out = String::from(
        "# Fuel per report-only call, the most a run may reach being this times 1.10.\n\
         # Written by `cargo run --release -- --write-ratchet`; see README.md.\n",
    );
    for m in measured.iter().filter(|m| !m.gating) {
        if let Some(fuel) = m.fuel {
            out.push_str(&format!("{}\t{}\t{}\t{fuel}\n", m.contract, m.case, m.call));
        }
    }
    out
}

/// The recorded figures, by (contract, case, call).
fn parse_ratchet(text: &str) -> Result<BTreeMap<(String, String, String), u64>> {
    let mut out = BTreeMap::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let parts: Vec<&str> = line.split('\t').collect();
        let [contract, case, call, fuel] = parts[..] else {
            bail!("ratchet line not contract, case, call, fuel: {line}");
        };
        out.insert(
            (contract.into(), case.into(), call.into()),
            fuel.parse()
                .with_context(|| format!("ratchet fuel: {line}"))?,
        );
    }
    Ok(out)
}

/// Each report-only call over its recorded figure by more than
/// [`RATCHET_PERCENT`], past the ceiling where it had a figure, or measured
/// with none recorded (a new call must be recorded to be held).
fn ratchet_failures(
    measured: &[Measured],
    recorded: &BTreeMap<(String, String, String), u64>,
) -> Vec<String> {
    let mut out = Vec::new();
    for m in measured.iter().filter(|m| !m.gating) {
        let key = (m.contract.to_string(), m.case.clone(), m.call.to_string());
        let name = format!("{} / {} / {}", m.contract, m.case, m.call);
        match (recorded.get(&key), m.fuel) {
            (None, _) => out.push(format!(
                "{name}: no recorded figure; run with --write-ratchet and commit {RATCHET_FILE}"
            )),
            (Some(was), None) => out.push(format!(
                "{name}: past the ceiling, where {} was recorded",
                group(*was)
            )),
            (Some(was), Some(now))
                if now as u128 * 100 > *was as u128 * RATCHET_PERCENT as u128 =>
            {
                out.push(format!(
                    "{name}: {} fuel, more than {}% of the {} recorded",
                    group(now),
                    RATCHET_PERCENT,
                    group(*was)
                ))
            }
            _ => {}
        }
    }
    out
}

fn main() -> ExitCode {
    let outcome = run();
    if let Err(e) = &outcome {
        eprintln!("::error::contract budget harness failed: {e:#}");
    }
    ExitCode::from(exit_code(&outcome))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ratchet holds each report-only call to 110% of its recorded
    /// figure, fails one with no figure or past the ceiling, and ignores
    /// gating calls (the budget holds those). Red with any of the three
    /// dropped. Also seen failing on the real run (README).
    #[test]
    fn the_ratchet_holds_report_only_calls_to_their_figures() {
        let recorded = parse_ratchet("# c\nstore\tcase\tcall\t1000\n").unwrap();
        let at = |fuel: Option<u64>, gating: bool| {
            let mut m = measured(gating, fuel, None);
            m.contract = "store";
            m.case = "case".into();
            m.call = "call";
            m
        };
        assert!(ratchet_failures(&[at(Some(1100), false)], &recorded).is_empty());
        assert_eq!(
            ratchet_failures(&[at(Some(1101), false)], &recorded).len(),
            1
        );
        assert_eq!(ratchet_failures(&[at(None, false)], &recorded).len(), 1);
        assert!(ratchet_failures(&[at(Some(5000), true)], &recorded).is_empty());
        let mut new = at(Some(1), false);
        new.case = "another".into();
        assert_eq!(ratchet_failures(&[new], &recorded).len(), 1);
        let written = write_ratchet_file(&[at(Some(7), false), at(Some(9), true)]);
        assert_eq!(parse_ratchet(&written).unwrap().len(), 1);
    }

    fn measured(gating: bool, fuel: Option<u64>, trap: Option<&str>) -> Measured {
        Measured {
            contract: "c",
            gating,
            tracked_by: "an issue",
            case: "case".into(),
            call: "call",
            fuel,
            trap: trap.map(str::to_string),
            host_calls: 0,
            timing: None,
        }
    }

    /// The three ways a call is over: fuel above the budget, past the
    /// ceiling (`fuel: None`), and a trap or refusal under the budget.
    fn over_kinds(gating: bool) -> [Measured; 3] {
        [
            measured(gating, Some(BUDGET_FUEL + 1), None),
            measured(gating, None, Some("ran past the fuel ceiling")),
            measured(gating, Some(1), Some("trapped: out of memory")),
        ]
    }

    #[test]
    fn an_over_call_of_a_gating_contract_fails_the_run() {
        for m in over_kinds(true) {
            assert!(m.fails_run() && !m.warns(), "{:?} {:?}", m.fuel, m.trap);
            assert_eq!(verdict(&m), "FAIL");
            let ms = [m];
            assert_eq!(gating_failures(&ms).len(), 1);
        }
    }

    #[test]
    fn an_over_call_of_a_report_only_contract_only_warns() {
        for m in over_kinds(false) {
            assert!(m.warns() && !m.fails_run(), "{:?} {:?}", m.fuel, m.trap);
            assert_eq!(verdict(&m), "WARN");
            let ms = [m];
            assert!(gating_failures(&ms).is_empty());
        }
    }

    #[test]
    fn a_call_within_budget_passes_either_way() {
        for gating in [true, false] {
            for fuel in [0, BUDGET_FUEL] {
                let m = measured(gating, Some(fuel), None);
                assert!(!m.over() && !m.fails_run() && !m.warns());
                assert_eq!(verdict(&m), "pass");
            }
        }
    }

    #[test]
    fn a_mixed_run_fails_only_on_its_gating_calls() {
        let ms = [
            measured(true, Some(1), None),
            measured(false, Some(BUDGET_FUEL * 10), None),
            measured(false, None, Some("trapped")),
            measured(true, Some(BUDGET_FUEL + 1), None),
        ];
        let failing = gating_failures(&ms);
        assert_eq!(failing.len(), 1);
        assert_eq!(failing[0].fuel, Some(BUDGET_FUEL + 1));
    }

    #[test]
    fn exit_codes() {
        assert_eq!(exit_code(&Ok(true)), 0);
        assert_eq!(exit_code(&Ok(false)), 1);
        assert_eq!(exit_code(&Err(anyhow!("harness"))), 2);
    }

    /// `report` answers `true` exactly when no gating call is over, which
    /// `exit_code` turns into 0, and a report-only failure does not change
    /// that.
    #[test]
    fn report_passes_a_run_whose_only_failures_are_report_only() {
        let ok = report(&over_kinds(false), &[], None).expect("report");
        assert_eq!(exit_code(&Ok(ok)), 0);
        let ok = report(&over_kinds(true), &[], None).expect("report");
        assert_eq!(exit_code(&Ok(ok)), 1);
    }
}
