//! A delegate host: the node's side of the delegate ABI, over wasmtime.
//!
//! Mirrors what freenet-core does for one delegate call
//! (`wasm_runtime/delegate/execution.rs::exec_inbound` and the host functions
//! in `wasm_runtime/native_api.rs`), for exactly the imports the Harvest
//! delegate declares:
//!
//! * `freenet_delegate_secrets.*` -- the persistent per-delegate secret store,
//!   with the node's return codes (`freenet_stdlib::delegate_host::error_codes`).
//! * `freenet_rand.__frnt__rand__rand_bytes` -- the node's RNG. Here it is a
//!   SEEDED ChaCha stream, so a run is reproducible to the unit of fuel.
//! * `freenet_time.__frnt__time__utc_now` -- the node writes its own
//!   `chrono::DateTime<Utc>` into guest memory; so does this, from a fixed
//!   instant that the scenario advances explicitly.
//!
//! Any import this host does not provide makes instantiation FAIL, rather
//! than silently stubbing it: a new host capability the delegate starts using
//! has to be added here deliberately, or the check goes red.
//!
//! One call = a fresh instance, `__frnt_set_id`, three buffers written through
//! `__frnt__initiate_buffer` (parameters, origin, inbound message), then
//! `process(params, origin, inbound)`. Only `process` is metered: it is the
//! guest entry the node's per-call wall-clock limit is applied to.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use freenet_stdlib::prelude::{
    bincode, DelegateError, InboundDelegateMsg, MessageOrigin, OutboundDelegateMsg,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use wasmtime::{Caller, Config, Engine, Extern, Instance, Linker, Memory, Module, OptLevel, Store};

// freenet_stdlib::delegate_host::error_codes, which is `cfg(target_family =
// "wasm")`-adjacent in places; the values are the ABI, so they are spelled out.
const ERR_SECRET_NOT_FOUND: i32 = -2;
const ERR_INVALID_PARAM: i32 = -4;
const ERR_BUFFER_TOO_SMALL: i32 = -6;
const ERR_MEMORY_BOUNDS: i32 = -7;

/// Fuel handed to one `process` call. Far above any budget, so an
/// over-budget handler is measured rather than cut off, but finite, so a
/// runaway loop ends the run instead of hanging CI.
pub const FUEL_CEILING: u64 = 1_000_000_000_000;

/// The node's cap on a delegate's linear memory: `DEFAULT_MAX_MEMORY_PAGES`
/// (4096 pages of 64 KiB) in freenet-core's `wasm_runtime/engine.rs`,
/// enforced by its `ResourceLimiter`. A handler that needs more fails there,
/// so it fails here too.
pub const MAX_MEMORY_BYTES: usize = 4096 * 64 * 1024;

/// The node keeps this secret namespace to itself: its `list_secrets` never
/// shows a delegate a key under it (`secrets_store/store.rs`, #4117).
const RESERVED_PREFIX: &[u8] = b"\0freenet-migrate/";

/// The secret store and the other host state one delegate "lives" on.
pub struct HostState {
    pub secrets: BTreeMap<Vec<u8>, Vec<u8>>,
    rng: ChaCha20Rng,
    pub now: DateTime<Utc>,
    memory: Option<Memory>,
    /// Host-function calls made during the current `process` call, and the
    /// time spent in them. Neither is judged: they let `--calibrate` separate
    /// guest time (what fuel measures) from host time (what it does not).
    host_calls: u64,
    host_time: Duration,
    /// Secret writes and removals in the current call: on a node each is an
    /// encrypted, fsync'd file write, which fuel does not see.
    host_writes: u64,
}

impl wasmtime::ResourceLimiter for HostState {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= MAX_MEMORY_BYTES)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(true)
    }
}

impl HostState {
    pub fn new(seed: u64, now: DateTime<Utc>) -> Self {
        Self {
            secrets: BTreeMap::new(),
            rng: ChaCha20Rng::seed_from_u64(seed),
            now,
            memory: None,
            host_calls: 0,
            host_time: Duration::ZERO,
            host_writes: 0,
        }
    }
}

/// What one `process` call cost and answered.
pub struct CallOutcome {
    /// Fuel `process` consumed, or `None` if it ran past [`FUEL_CEILING`].
    pub fuel: Option<u64>,
    pub result: Result<Vec<OutboundDelegateMsg>, String>,
    /// Wall-clock time of the `process` call (not what is judged).
    pub metered_wall: Duration,
    /// Host-function calls `process` made, and the wall time spent in them.
    pub host_calls: u64,
    pub host_time: Duration,
    /// Secret writes and removals `process` made.
    pub host_writes: u64,
}

pub struct Host {
    metered: Engine,
    metered_module: Module,
    /// A second engine configured like the node's (no fuel), used only by
    /// `--calibrate` to time the same call unmetered.
    node_like: Option<(Engine, Module)>,
    pub state: HostState,
    next_id: i64,
}

fn node_config() -> Config {
    let mut config = Config::new();
    // freenet-core compiles guest code with Cranelift at OptLevel::None
    // (`engine/wasmtime_engine.rs::create_engine`). Fuel counts do not depend
    // on it, but the calibration's wall-clock times do, so match it.
    config.cranelift_opt_level(OptLevel::None);
    config
}

impl Host {
    pub fn new(wasm: &[u8], state: HostState, calibrate: bool) -> Result<Self> {
        let mut config = node_config();
        config.consume_fuel(true);
        let metered = Engine::new(&config)?;
        let metered_module = Module::new(&metered, wasm)
            .map_err(|e| anyhow!("compile delegate (metered): {e:#}"))?;
        let node_like = if calibrate {
            let mut config = node_config();
            // The node always enables epoch interruption (#4861); it adds a
            // check at every loop back-edge, so it belongs in the timing.
            config.epoch_interruption(true);
            let engine = Engine::new(&config)?;
            let module = Module::new(&engine, wasm)
                .map_err(|e| anyhow!("compile delegate (node-like): {e:#}"))?;
            Some((engine, module))
        } else {
            None
        };
        Ok(Self {
            metered,
            metered_module,
            node_like,
            state,
            next_id: 1,
        })
    }

    /// Run one inbound message through `process`, metered. Secrets written by
    /// the call persist into the next one, as on a node.
    pub fn call(
        &mut self,
        origin: Option<&MessageOrigin>,
        msg: &InboundDelegateMsg<'_>,
    ) -> Result<CallOutcome> {
        let msg = bincode::serialize(msg)?;
        self.call_raw(origin, &msg)
    }

    /// [`Host::call`] for an inbound message already bincode-encoded (the
    /// background runs, which stdlib 0.8.5 has no type for).
    pub fn call_raw(&mut self, origin: Option<&MessageOrigin>, msg: &[u8]) -> Result<CallOutcome> {
        let origin = match origin {
            Some(o) => bincode::serialize(o)?,
            None => Vec::new(),
        };
        let engine = self.metered.clone();
        let module = self.metered_module.clone();
        let now = self.state.now;
        let state = std::mem::replace(&mut self.state, HostState::new(0, now));
        let id = self.next_id;
        self.next_id += 1;
        let (state, outcome) = run_once(&engine, &module, state, id, &origin, msg, true)?;
        self.state = state;
        Ok(outcome)
    }

    /// Time the same call unmetered on a node-like engine, from a snapshot of
    /// the current state, and throw that run's effects away. Returns the
    /// wall-clock time of `process`. The RNG is snapshotted too, so the timed
    /// run executes the identical path the metered run will.
    pub fn time_unmetered(
        &mut self,
        origin: Option<&MessageOrigin>,
        msg: &InboundDelegateMsg<'_>,
    ) -> Result<(Duration, Duration)> {
        let (engine, module) = self
            .node_like
            .clone()
            .ok_or_else(|| anyhow!("host built without calibration"))?;
        let msg = bincode::serialize(msg)?;
        let origin = match origin {
            Some(o) => bincode::serialize(o)?,
            None => Vec::new(),
        };
        let snapshot = HostState {
            secrets: self.state.secrets.clone(),
            rng: self.state.rng.clone(),
            now: self.state.now,
            memory: None,
            host_calls: 0,
            host_time: Duration::ZERO,
            host_writes: 0,
        };
        let (_, outcome) = run_once(&engine, &module, snapshot, 0, &origin, &msg, false)?;
        outcome
            .result
            .map_err(|e| anyhow!("unmetered run failed: {e}"))?;
        Ok((outcome.metered_wall, outcome.host_time))
    }
}

fn run_once(
    engine: &Engine,
    module: &Module,
    state: HostState,
    id: i64,
    origin: &[u8],
    msg: &[u8],
    metered: bool,
) -> Result<(HostState, CallOutcome)> {
    let mut linker: Linker<HostState> = Linker::new(engine);
    register_imports(&mut linker)?;
    let mut store = Store::new(engine, state);
    store.limiter(|state| state);
    if metered {
        // Instantiation and buffer setup are not what the node's limit is
        // applied to, and are not what this check judges.
        store.set_fuel(u64::MAX / 2)?;
    } else {
        store.set_epoch_deadline(1 << 40);
    }
    let instance: Instance = linker.instantiate(&mut store, module).map_err(|e| {
        anyhow!("instantiate the delegate (a host import it needs may be missing): {e:#}")
    })?;
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| anyhow!("delegate exports no memory"))?;
    store.data_mut().memory = Some(memory);

    if let Some(set_id) = instance.get_func(&mut store, "__frnt_set_id") {
        set_id.typed::<i64, ()>(&store)?.call(&mut store, id)?;
    }

    let params = write_buffer(&mut store, &instance, &[])?; // DELEGATE_PARAMETERS = &[]
    let origin = write_buffer(&mut store, &instance, origin)?;
    let inbound = write_buffer(&mut store, &instance, msg)?;

    let process = instance.get_typed_func::<(i64, i64, i64), i64>(&mut store, "process")?;
    if metered {
        store.set_fuel(FUEL_CEILING)?;
    }
    store.data_mut().host_calls = 0;
    store.data_mut().host_time = Duration::ZERO;
    store.data_mut().host_writes = 0;
    let started = Instant::now();
    let ret = process.call(&mut store, (params, origin, inbound));
    let wall = started.elapsed();
    let fuel = if metered {
        let left = store.get_fuel()?;
        Some(FUEL_CEILING - left)
    } else {
        None
    };

    let (fuel, result) = match ret {
        Ok(ptr) => (fuel, read_result(&mut store, memory, ptr)?),
        Err(trap) => {
            let out_of_fuel = matches!(
                trap.downcast_ref::<wasmtime::Trap>(),
                Some(wasmtime::Trap::OutOfFuel)
            );
            if out_of_fuel {
                (
                    None,
                    Err(format!("ran past the {FUEL_CEILING} fuel ceiling")),
                )
            } else {
                (fuel, Err(format!("trapped: {trap:#}")))
            }
        }
    };
    let state = store.into_data();
    let (host_calls, host_time, host_writes) =
        (state.host_calls, state.host_time, state.host_writes);
    Ok((
        HostState {
            memory: None,
            ..state
        },
        CallOutcome {
            fuel,
            result,
            metered_wall: wall,
            host_calls,
            host_time,
            host_writes,
        },
    ))
}

/// `__frnt__initiate_buffer(len)`, then copy `data` in and set the write
/// cursor, as `BufferMut::write` does on the node.
///
/// `BufferBuilder` is `#[repr(C)] { start: i64, capacity: u32, last_read: i64,
/// last_write: i64 }`: offsets 0, 8, 16, 24 on wasm32 as on the host.
fn write_buffer(store: &mut Store<HostState>, instance: &Instance, data: &[u8]) -> Result<i64> {
    let init = instance.get_typed_func::<u32, i64>(&mut *store, "__frnt__initiate_buffer")?;
    let builder = init.call(&mut *store, data.len() as u32)?;
    let memory = store.data().memory.expect("memory recorded");
    let mem = memory.data_mut(&mut *store);
    let b = builder as usize;
    let start = i64::from_le_bytes(mem[b..b + 8].try_into()?) as usize;
    let capacity = u32::from_le_bytes(mem[b + 8..b + 12].try_into()?) as usize;
    let last_write = i64::from_le_bytes(mem[b + 24..b + 32].try_into()?) as usize;
    if capacity < data.len() {
        bail!("buffer of {capacity} bytes for {} bytes", data.len());
    }
    mem[start..start + data.len()].copy_from_slice(data);
    mem[last_write..last_write + 4].copy_from_slice(&(data.len() as u32).to_le_bytes());
    Ok(builder)
}

/// `DelegateInterfaceResult { ptr: i64, size: u32 }` at `ptr`, pointing at the
/// bincode of `Result<Vec<OutboundDelegateMsg>, DelegateError>`.
fn read_result(
    store: &mut Store<HostState>,
    memory: Memory,
    ptr: i64,
) -> Result<Result<Vec<OutboundDelegateMsg>, String>> {
    let mem = memory.data(&*store);
    let p = ptr as usize;
    let data = i64::from_le_bytes(mem[p..p + 8].try_into()?) as usize;
    let size = u32::from_le_bytes(mem[p + 8..p + 12].try_into()?) as usize;
    let bytes = mem
        .get(data..data + size)
        .ok_or_else(|| anyhow!("result out of bounds"))?
        .to_vec();
    let decoded: Result<Vec<OutboundDelegateMsg>, DelegateError> =
        bincode::deserialize(&bytes).context("decode the delegate's result")?;
    Ok(decoded.map_err(|e| format!("{e}")))
}

fn memory_of(caller: &mut Caller<'_, HostState>) -> Memory {
    match caller.get_export("memory") {
        Some(Extern::Memory(m)) => m,
        _ => caller.data().memory.expect("memory recorded"),
    }
}

fn read_guest(caller: &mut Caller<'_, HostState>, ptr: i64, len: i32) -> Option<Vec<u8>> {
    if ptr < 0 || len < 0 {
        return None;
    }
    let memory = memory_of(caller);
    let data = memory.data(&*caller);
    data.get(ptr as usize..(ptr as usize).checked_add(len as usize)?)
        .map(<[u8]>::to_vec)
}

fn write_guest(caller: &mut Caller<'_, HostState>, ptr: i64, bytes: &[u8]) -> bool {
    if ptr < 0 {
        return false;
    }
    let memory = memory_of(caller);
    let data = memory.data_mut(&mut *caller);
    match data.get_mut(ptr as usize..ptr as usize + bytes.len()) {
        Some(dst) => {
            dst.copy_from_slice(bytes);
            true
        }
        None => false,
    }
}

/// Run a host function body, counting it and timing it.
fn timed<R>(
    caller: &mut Caller<'_, HostState>,
    body: impl FnOnce(&mut Caller<'_, HostState>) -> R,
) -> R {
    let started = Instant::now();
    let r = body(caller);
    let state = caller.data_mut();
    state.host_calls += 1;
    state.host_time += started.elapsed();
    r
}

fn register_imports(linker: &mut Linker<HostState>) -> Result<()> {
    const SECRETS: &str = "freenet_delegate_secrets";

    linker.func_wrap(
        SECRETS,
        "__frnt__delegate__get_secret_len",
        |mut c: Caller<'_, HostState>, key_ptr: i64, key_len: i32| -> i32 {
            timed(&mut c, |caller| {
                let Some(key) = read_guest(caller, key_ptr, key_len) else {
                    return ERR_MEMORY_BOUNDS;
                };
                match caller.data().secrets.get(&key) {
                    Some(v) => v.len().min(i32::MAX as usize) as i32,
                    None => ERR_SECRET_NOT_FOUND,
                }
            })
        },
    )?;

    linker.func_wrap(
        SECRETS,
        "__frnt__delegate__get_secret",
        |mut c: Caller<'_, HostState>,
         key_ptr: i64,
         key_len: i32,
         out_ptr: i64,
         out_len: i32|
         -> i32 {
            timed(&mut c, |caller| {
                if out_len < 0 {
                    return ERR_INVALID_PARAM;
                }
                let Some(key) = read_guest(caller, key_ptr, key_len) else {
                    return ERR_MEMORY_BOUNDS;
                };
                let Some(value) = caller.data().secrets.get(&key).cloned() else {
                    return ERR_SECRET_NOT_FOUND;
                };
                if value.len() > out_len as usize {
                    return ERR_BUFFER_TOO_SMALL;
                }
                if value.is_empty() {
                    return 0;
                }
                if !write_guest(caller, out_ptr, &value) {
                    return ERR_MEMORY_BOUNDS;
                }
                value.len() as i32
            })
        },
    )?;

    linker.func_wrap(
        SECRETS,
        "__frnt__delegate__set_secret",
        |mut c: Caller<'_, HostState>,
         key_ptr: i64,
         key_len: i32,
         val_ptr: i64,
         val_len: i32|
         -> i32 {
            timed(&mut c, |caller| {
                let (Some(key), Some(value)) = (
                    read_guest(caller, key_ptr, key_len),
                    read_guest(caller, val_ptr, val_len),
                ) else {
                    return ERR_MEMORY_BOUNDS;
                };
                caller.data_mut().host_writes += 1;
                caller.data_mut().secrets.insert(key, value);
                0
            })
        },
    )?;

    linker.func_wrap(
        SECRETS,
        "__frnt__delegate__has_secret",
        |mut c: Caller<'_, HostState>, key_ptr: i64, key_len: i32| -> i32 {
            timed(&mut c, |caller| {
                let Some(key) = read_guest(caller, key_ptr, key_len) else {
                    return ERR_MEMORY_BOUNDS;
                };
                i32::from(caller.data().secrets.contains_key(&key))
            })
        },
    )?;

    linker.func_wrap(
        SECRETS,
        "__frnt__delegate__remove_secret",
        |mut c: Caller<'_, HostState>, key_ptr: i64, key_len: i32| -> i32 {
            timed(&mut c, |caller| {
                let Some(key) = read_guest(caller, key_ptr, key_len) else {
                    return ERR_MEMORY_BOUNDS;
                };
                caller.data_mut().host_writes += 1;
                match caller.data_mut().secrets.remove(&key) {
                    Some(_) => 0,
                    None => ERR_SECRET_NOT_FOUND,
                }
            })
        },
    )?;

    // Each record: a 4-byte little-endian length, then the key
    // (`encode_secret_key_list` on the node, `decode_secret_key_list` in the
    // guest).
    fn list(state: &HostState, prefix: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for key in state
            .secrets
            .keys()
            .filter(|k| k.starts_with(prefix) && !k.starts_with(RESERVED_PREFIX))
        {
            out.extend_from_slice(&(key.len() as u32).to_le_bytes());
            out.extend_from_slice(key);
        }
        out
    }

    linker.func_wrap(
        SECRETS,
        "__frnt__delegate__list_secrets_len",
        |mut c: Caller<'_, HostState>, prefix_ptr: i64, prefix_len: i32| -> i32 {
            timed(&mut c, |caller| {
                let Some(prefix) = read_guest(caller, prefix_ptr, prefix_len) else {
                    return ERR_MEMORY_BOUNDS;
                };
                list(caller.data(), &prefix).len().min(i32::MAX as usize) as i32
            })
        },
    )?;

    linker.func_wrap(
        SECRETS,
        "__frnt__delegate__list_secrets",
        |mut c: Caller<'_, HostState>,
         prefix_ptr: i64,
         prefix_len: i32,
         out_ptr: i64,
         out_len: i32|
         -> i32 {
            timed(&mut c, |caller| {
                if out_len < 0 {
                    return ERR_INVALID_PARAM;
                }
                let Some(prefix) = read_guest(caller, prefix_ptr, prefix_len) else {
                    return ERR_MEMORY_BOUNDS;
                };
                let bytes = list(caller.data(), &prefix);
                if bytes.is_empty() {
                    return 0;
                }
                if bytes.len() > out_len as usize {
                    return ERR_BUFFER_TOO_SMALL;
                }
                if !write_guest(caller, out_ptr, &bytes) {
                    return ERR_MEMORY_BOUNDS;
                }
                bytes.len() as i32
            })
        },
    )?;

    linker.func_wrap(
        "freenet_rand",
        "__frnt__rand__rand_bytes",
        |mut c: Caller<'_, HostState>, _id: i64, ptr: i64, len: u32| {
            timed(&mut c, |caller| {
                let mut bytes = vec![0u8; len as usize];
                caller.data_mut().rng.fill_bytes(&mut bytes);
                assert!(write_guest(caller, ptr, &bytes), "rand_bytes out of bounds");
            })
        },
    )?;

    linker.func_wrap(
        "freenet_time",
        "__frnt__time__utc_now",
        |mut c: Caller<'_, HostState>, _id: i64, ptr: i64| {
            timed(&mut c, |caller| {
                // The node writes its own `DateTime<Utc>` straight into guest
                // memory (`native_api::time::utc_now`); the layout (12 bytes,
                // align 4) is the same on x86_64 and wasm32.
                let now = caller.data().now;
                const N: usize = std::mem::size_of::<DateTime<Utc>>();
                let bytes: [u8; N] = unsafe { std::mem::transmute_copy(&now) };
                assert!(write_guest(caller, ptr, &bytes), "utc_now out of bounds");
            })
        },
    )?;

    Ok(())
}
