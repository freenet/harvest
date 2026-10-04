//! A contract host: the node's side of the contract ABI, over wasmtime.
//!
//! Mirrors what freenet-core does for one contract call
//! (`wasm_runtime/contract.rs` and `runtime.rs::write_streaming_buf`), for
//! exactly the import the Harvest contracts declare:
//!
//! * `freenet_contract_io.__frnt__fill_buffer` -- the streaming refill. The
//!   node writes each argument into a buffer of at most 64 KiB
//!   (`STREAMING_BUF_CAP`), a `[total_len: u32]` header then as much data as
//!   fits, and keeps the rest; the guest asks for the next chunk when it has
//!   read the last (`native_api::fill_buffer_impl`). A 4 MiB state is
//!   therefore read in about 64 refills, as on the node.
//!
//! Any import this host does not provide makes instantiation FAIL (exit 2)
//! rather than being silently stubbed: a host capability a contract starts
//! using has to be added here deliberately, or the check goes red.
//!
//! One call = a fresh instance, `__frnt_set_id`, three buffers written
//! through `__frnt__initiate_buffer`, then the entry point
//! (`validate_state`, `update_state`, `summarize_state` or
//! `get_state_delta`), as the node creates an instance per call
//! (`prepare_contract_call`). Only the entry point is metered: it is the
//! guest call the node's per-call wall-clock limit is applied to.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use wasmtime::{Caller, Config, Engine, Extern, Instance, Linker, Memory, Module, OptLevel, Store};

/// Fuel handed to one call. Far above any budget, so an over-budget call is
/// measured rather than cut off, but finite, so a runaway loop ends the run
/// instead of hanging CI.
pub const FUEL_CEILING: u64 = 1_000_000_000_000;

/// The node's cap on a contract's linear memory: `DEFAULT_MAX_MEMORY_PAGES`
/// (4096 pages of 64 KiB) in freenet-core's `wasm_runtime/engine.rs`,
/// enforced by its `ResourceLimiter`.
pub const MAX_MEMORY_BYTES: usize = 4096 * 64 * 1024;

/// The node's streaming buffer cap (`wasm_runtime/contract.rs`,
/// `STREAMING_BUF_CAP`).
const STREAMING_BUF_CAP: usize = 64 * 1024;

/// The node's linear-memory reservation, guard and stack, as in
/// `engine/wasmtime_engine.rs::create_engine`.
const NODE_MEMORY_RESERVATION: u64 = MAX_MEMORY_BYTES as u64;
const NODE_MEMORY_GUARD: u64 = 65536;
const NODE_WASM_STACK: usize = 8 * 1024 * 1024;

/// What the host holds for one call.
struct HostState {
    memory: Option<Memory>,
    /// The part of each argument that did not fit its buffer, by the
    /// buffer's `BufferBuilder` address: `(data, cursor)`. The node keys
    /// `CONTRACT_IO` by `(instance id, buffer pointer)`; one call is one
    /// instance here, so the pointer is enough.
    pending: HashMap<i64, (Vec<u8>, usize)>,
    host_calls: u64,
    host_time: Duration,
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
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // The node's `MAX_TABLE_ELEMENTS`.
        Ok(desired <= 10_000)
    }
}

/// What one entry-point call cost and returned.
pub struct CallOutcome {
    /// Fuel the entry point consumed, or `None` if it ran past
    /// [`FUEL_CEILING`].
    pub fuel: Option<u64>,
    /// The bincode bytes of the `Result<T, ContractError>` the entry point
    /// returned, or why there are none (a trap).
    pub result: Result<Vec<u8>, String>,
    /// Refill calls the guest made, and the wall time spent in them.
    pub host_calls: u64,
    pub host_time: Duration,
    /// Wall time of the entry point (not what is judged).
    pub wall: Duration,
}

/// One compiled contract, on a metered engine and (for `--calibrate`) a
/// node-like one.
pub struct Contract {
    metered: (Engine, Module),
    node_like: Option<(Engine, Module)>,
}

fn node_config() -> Config {
    let mut config = Config::new();
    // freenet-core compiles guest code with Cranelift at OptLevel::None.
    // Fuel counts do not depend on it, but the calibration's wall-clock times
    // do, so match it.
    config.cranelift_opt_level(OptLevel::None);
    // And its memory layout: a 256 MiB reservation, a 64 KiB guard and no
    // room to grow in place. With so small a guard Cranelift compiles
    // explicit bounds checks, which are part of the node's wall-clock time.
    config.memory_reservation(NODE_MEMORY_RESERVATION);
    config.memory_guard_size(NODE_MEMORY_GUARD);
    config.memory_reservation_for_growth(0);
    config.max_wasm_stack(NODE_WASM_STACK);
    config.async_stack_size(NODE_WASM_STACK * 2);
    config
}

impl Contract {
    pub fn new(wasm: &[u8], calibrate: bool) -> Result<Self> {
        let mut config = node_config();
        config.consume_fuel(true);
        let engine = Engine::new(&config)?;
        let module =
            Module::new(&engine, wasm).map_err(|e| anyhow!("compile contract (metered): {e:#}"))?;
        let node_like = if calibrate {
            let mut config = node_config();
            // The node always enables epoch interruption; it adds a check at
            // every loop back-edge, so it belongs in the timing.
            config.epoch_interruption(true);
            let engine = Engine::new(&config)?;
            let module = Module::new(&engine, wasm)
                .map_err(|e| anyhow!("compile contract (node-like): {e:#}"))?;
            Some((engine, module))
        } else {
            None
        };
        Ok(Self {
            metered: (engine, module),
            node_like,
        })
    }

    /// Call `entry(a, b, c)` metered, each argument already encoded as the
    /// node encodes it.
    pub fn call(&self, entry: &str, args: &[&[u8]]) -> Result<CallOutcome> {
        let (engine, module) = &self.metered;
        run_once(engine, module, entry, args, true)
    }

    /// Time the same call unmetered on the node-like engine. Returns the
    /// wall time of the entry point and the part of it spent in the host.
    pub fn time_unmetered(&self, entry: &str, args: &[&[u8]]) -> Result<(Duration, Duration)> {
        let (engine, module) = self
            .node_like
            .as_ref()
            .ok_or_else(|| anyhow!("contract built without calibration"))?;
        let outcome = run_once(engine, module, entry, args, false)?;
        outcome
            .result
            .map_err(|e| anyhow!("unmetered run failed: {e}"))?;
        Ok((outcome.wall, outcome.host_time))
    }
}

fn run_once(
    engine: &Engine,
    module: &Module,
    entry: &str,
    args: &[&[u8]],
    metered: bool,
) -> Result<CallOutcome> {
    let mut linker: Linker<HostState> = Linker::new(engine);
    register_imports(&mut linker)?;
    let mut store = Store::new(
        engine,
        HostState {
            memory: None,
            pending: HashMap::new(),
            host_calls: 0,
            host_time: Duration::ZERO,
        },
    );
    store.limiter(|state| state);
    if metered {
        // Instantiation and buffer setup are not what the node's limit is
        // applied to, and are not what this check judges.
        store.set_fuel(u64::MAX / 2)?;
    } else {
        store.set_epoch_deadline(1 << 40);
    }
    let instance: Instance = linker.instantiate(&mut store, module).map_err(|e| {
        anyhow!("instantiate the contract (a host import it needs may be missing): {e:#}")
    })?;
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| anyhow!("contract exports no memory"))?;
    store.data_mut().memory = Some(memory);

    // The node hands every instance an id from its process-wide allocator;
    // the guest passes it back on each refill.
    const INSTANCE_ID: i64 = 1;
    if let Some(set_id) = instance.get_func(&mut store, "__frnt_set_id") {
        set_id
            .typed::<i64, ()>(&store)?
            .call(&mut store, INSTANCE_ID)?;
    }

    let mut ptrs = Vec::with_capacity(args.len());
    for data in args {
        ptrs.push(write_streaming_buf(&mut store, &instance, data)?);
    }

    // `summarize_state(parameters, state)` takes two buffers; the other
    // entry points take three.
    if metered {
        store.set_fuel(FUEL_CEILING)?;
    }
    let started = Instant::now();
    let ret = match ptrs[..] {
        [a, b] => instance
            .get_typed_func::<(i64, i64), i64>(&mut store, entry)?
            .call(&mut store, (a, b)),
        [a, b, c] => instance
            .get_typed_func::<(i64, i64, i64), i64>(&mut store, entry)?
            .call(&mut store, (a, b, c)),
        _ => bail!("{entry}: {} arguments", ptrs.len()),
    };
    let wall = started.elapsed();
    let fuel = if metered {
        Some(FUEL_CEILING - store.get_fuel()?)
    } else {
        None
    };
    let (fuel, result) = match ret {
        Ok(ptr) => (fuel, Ok(read_result(&store, memory, ptr)?)),
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
    let state = store.data();
    Ok(CallOutcome {
        fuel,
        result,
        host_calls: state.host_calls,
        host_time: state.host_time,
        wall,
    })
}

/// `BufferBuilder` is `#[repr(C)] { start: i64, capacity: u32, last_read:
/// i64, last_write: i64 }`: offsets 0, 8, 16, 24 on wasm32 as on the host.
/// `last_read` and `last_write` point at `u32` cursors.
struct Builder {
    start: usize,
    capacity: usize,
    last_read: usize,
    last_write: usize,
}

fn builder_at(mem: &[u8], ptr: i64) -> Result<Builder> {
    let b = usize::try_from(ptr)?;
    let word = |at: usize| -> Result<usize> {
        Ok(i64::from_le_bytes(
            mem.get(b + at..b + at + 8)
                .ok_or_else(|| anyhow!("buffer builder out of bounds"))?
                .try_into()?,
        ) as usize)
    };
    Ok(Builder {
        start: word(0)?,
        capacity: u32::from_le_bytes(
            mem.get(b + 8..b + 12)
                .ok_or_else(|| anyhow!("buffer builder out of bounds"))?
                .try_into()?,
        ) as usize,
        last_read: word(16)?,
        last_write: word(24)?,
    })
}

/// `Runtime::write_streaming_buf`: a buffer of at most
/// [`STREAMING_BUF_CAP`] bytes holding a `[total_len: u32]` header and as
/// much of `data` as fits; the rest is kept for [`fill_buffer`].
fn write_streaming_buf(
    store: &mut Store<HostState>,
    instance: &Instance,
    data: &[u8],
) -> Result<i64> {
    const HEADER: usize = 4;
    if data.len() > u32::MAX as usize {
        bail!("argument of {} bytes is over u32::MAX", data.len());
    }
    let cap = STREAMING_BUF_CAP.min(data.len() + HEADER);
    let init = instance.get_typed_func::<u32, i64>(&mut *store, "__frnt__initiate_buffer")?;
    let ptr = init.call(&mut *store, cap as u32)?;
    let memory = store.data().memory.expect("memory recorded");
    let mem = memory.data_mut(&mut *store);
    let b = builder_at(mem, ptr)?;
    if b.capacity < cap {
        bail!("buffer of {} bytes for {cap}", b.capacity);
    }
    let first = data.len().min(cap - HEADER);
    mem[b.start..b.start + HEADER].copy_from_slice(&(data.len() as u32).to_le_bytes());
    mem[b.start + HEADER..b.start + HEADER + first].copy_from_slice(&data[..first]);
    mem[b.last_write..b.last_write + 4].copy_from_slice(&((HEADER + first) as u32).to_le_bytes());
    if first < data.len() {
        store
            .data_mut()
            .pending
            .insert(ptr, (data[first..].to_vec(), 0));
    }
    Ok(ptr)
}

/// `native_api::fill_buffer_impl`: reset the buffer's cursors to 0, copy the
/// next chunk in, and return its length (0 at the end).
fn fill_buffer(caller: &mut Caller<'_, HostState>, buf_ptr: i64) -> u32 {
    let memory = match caller.get_export("memory") {
        Some(Extern::Memory(m)) => m,
        _ => caller.data().memory.expect("memory recorded"),
    };
    let Some((data, cursor)) = caller.data_mut().pending.remove(&buf_ptr) else {
        return 0;
    };
    if cursor >= data.len() {
        return 0;
    }
    let mem = memory.data_mut(&mut *caller);
    let Ok(b) = builder_at(mem, buf_ptr) else {
        return 0;
    };
    let chunk = (data.len() - cursor).min(b.capacity);
    mem[b.last_read..b.last_read + 4].copy_from_slice(&0u32.to_le_bytes());
    mem[b.start..b.start + chunk].copy_from_slice(&data[cursor..cursor + chunk]);
    mem[b.last_write..b.last_write + 4].copy_from_slice(&(chunk as u32).to_le_bytes());
    caller
        .data_mut()
        .pending
        .insert(buf_ptr, (data, cursor + chunk));
    chunk as u32
}

/// `ContractInterfaceResult { ptr: i64, kind: i32, size: u32 }` at `ptr`,
/// pointing at the bincode of `Result<T, ContractError>`.
fn read_result(store: &Store<HostState>, memory: Memory, ptr: i64) -> Result<Vec<u8>> {
    let mem = memory.data(store);
    let p = usize::try_from(ptr)?;
    let header = mem
        .get(p..p + 16)
        .ok_or_else(|| anyhow!("result header out of bounds"))?;
    let data = i64::from_le_bytes(header[0..8].try_into()?) as usize;
    let size = u32::from_le_bytes(header[12..16].try_into()?) as usize;
    Ok(mem
        .get(data..data + size)
        .ok_or_else(|| anyhow!("result out of bounds"))?
        .to_vec())
}

fn register_imports(linker: &mut Linker<HostState>) -> Result<()> {
    linker.func_wrap(
        "freenet_contract_io",
        "__frnt__fill_buffer",
        |mut caller: Caller<'_, HostState>, _id: i64, buf_ptr: i64| -> u32 {
            let started = Instant::now();
            let n = fill_buffer(&mut caller, buf_ptr);
            let state = caller.data_mut();
            state.host_calls += 1;
            state.host_time += started.elapsed();
            n
        },
    )?;
    Ok(())
}
