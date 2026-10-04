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

mod cases;
mod host;

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
    case: String,
    call: &'static str,
    fuel: Option<u64>,
    /// Why the call stopped without an answer: the fuel ceiling, or a trap
    /// (out of the node's 256 MiB memory, a panic). Either is a failure: on
    /// a node the update fails the same way.
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
            Update::Delta(d) => UpdateData::Delta(StateDelta::from(d.clone())),
            Update::State(s) => UpdateData::State(s.clone().into()),
        };
        let updates = bincode::serialize(&vec![update])?;

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
            expect_valid(case, "validate_state (incoming state)", &r)?;
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
        let merged = new_state(case, &r)?;
        if merged == case.held {
            bail!(
                "{} / {}: the update changed nothing, so the node would stop after \
                 update_state and the fixture is not exercising a real update",
                case.kind.name(),
                case.name
            );
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
        expect_valid(case, "validate_state (merged state)", &r)?;

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
        summary
            .map_err(|e| anyhow!("{} / {}: summarize_state: {e}", case.kind.name(), case.name))?;

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
        let delta: Result<StateDelta<'_>, ContractError> = bincode::deserialize(&r)?;
        let delta = delta
            .map_err(|e| anyhow!("{} / {}: get_state_delta: {e}", case.kind.name(), case.name))?;
        if delta.as_ref().is_empty() {
            bail!(
                "{} / {}: get_state_delta found nothing new for a co-host holding the old \
                 state, though the state changed",
                case.kind.name(),
                case.name
            );
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
            new_state(case, &r)?;
        }
        Ok(())
    }
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

fn print_line(m: &Measured) {
    let fuel = m.fuel.map_or("past the ceiling".into(), group);
    println!(
        "{:<10} {:<44} {:<52} {fuel:>17} / {} {:>7} {}",
        m.contract,
        m.case,
        m.call,
        group(BUDGET_FUEL),
        percent(m.fuel),
        if m.over() { "FAIL" } else { "pass" }
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
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--wasm-dir" => wasm_dir = args.next().ok_or_else(|| anyhow!("--wasm-dir DIR"))?.into(),
            "--calibrate" => calibrate_reps = 3,
            n if calibrate_reps > 0 && n.parse::<usize>().is_ok() => {
                calibrate_reps = n.parse().unwrap()
            }
            other => {
                bail!("unknown argument {other}; usage: [--wasm-dir DIR] [--calibrate [REPS]]")
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
    for case in cases::all()? {
        if let Err(e) = runner.run_case(&case) {
            failure = Some(e);
            break;
        }
    }

    let ok = report(&runner.measured, &hashes, failure.as_ref())?;
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
    let over: Vec<&Measured> = measured.iter().filter(|m| m.over()).collect();

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
            match (&m.trap, m.over()) {
                (Some(t), _) => format!(":x: **{}**", t.lines().next().unwrap_or(t)),
                (None, true) => ":x: **over budget**".into(),
                (None, false) => String::new(),
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
    } else if over.is_empty() {
        writeln!(md, "Every call is within budget.").ok();
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
    if let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)?
            .write_all(md.as_bytes())?;
    }

    println!();
    if over.is_empty() {
        println!("every call is within {} fuel", group(BUDGET_FUEL));
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

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("::error::contract budget harness failed: {e:#}");
            ExitCode::from(2)
        }
    }
}
