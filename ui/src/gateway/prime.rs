//! Writing to a contract the local node may not hold yet (harvest#119).
//!
//! # The failure this exists to prevent
//!
//! An UPDATE is applied by the contract's own WASM, so the node has to hold
//! the contract's code and parameters before it can take one. When it does
//! not, freenet-core does not queue the update: it starts fetching the
//! contract and answers the client with an error asking it to retry. That
//! error carries no correlation id, and the contract is named only inside its
//! English text, so the client has nothing to match it against.
//!
//! Harvest used to issue a priming GET and then the UPDATE back to back. Both
//! resolve when the WebSocket SEND succeeds, not when the node has done
//! anything, so on a fresh node the UPDATE arrived first and was bounced, and
//! nothing retried it. The launch audit caught exactly that live: a buyer's
//! first "Buy this" never reached the seller's mailbox.
//!
//! # What this does instead
//!
//! Every update waits for the node to ANSWER a GET for the same contract
//! before it is sent. That is correct by construction rather than by timing:
//! on the client-GET path freenet-core stores the fetched contract locally
//! (`get/op_ctx_task.rs::cache_contract_locally`, awaited) before it builds
//! the response it sends back, so a `GetResponse` for a contract proves the
//! node holds it at that moment. Any `GetResponse` for the contract counts,
//! including one answering a different request (the mailbox subscribe, say):
//! what it proves is about the node, not about the request.
//!
//! A GET that dead-ends produces no answer at all, so a deadline bounds the
//! wait. When it expires, or the node answers `NotFound`, the update is sent
//! anyway: that is exactly what happened before this module existed, so it
//! can only help, and whatever sits above (the mailbox's delivery check, a
//! bridge watch request's own re-request) still gets its chance.
//!
//! The GET does NOT subscribe. Priming is not interest: a subscription is a
//! standing signal to the network, and each caller that wants one already
//! asks for it separately. Its answer is still an ordinary `GetResponse`,
//! though, and goes through `on_contract_state` like any other: for a store
//! that re-runs the follow-ups a store state triggers (the reputation link,
//! purchase address watches, settlements, watch requests). Each of those is
//! already deduplicated (`settlements_submitted`, `custody_attempted`, the
//! watch request's landing grace), which is why a pre-write state coming
//! back cannot start a write loop.
//!
//! # Why this is at the choke point rather than at each caller
//!
//! Every contract write in the UI goes through [`update_contract`], and a
//! write to a contract the node might not hold is not special to messaging:
//! a buyer publishing a settlement writes to a seller's store, and a watch
//! request writes to a bridge's inbox. Deciding per call site whether the
//! node "must already" hold the contract is a claim about the node's hosting
//! policy, which evicts on demand; priming every write makes none. The cost
//! is one extra local GET per write, answered from the node's own store when
//! it does hold the contract.

use std::cell::RefCell;
use std::collections::HashMap;

use freenet_stdlib::prelude::{ContractInstanceId, ContractKey, UpdateData};
use futures::channel::oneshot;

/// How long an update waits for its priming GET to be answered before it is
/// sent anyway.
///
/// The same bound as a store opened from a link
/// (`store_link::LINK_LOAD_TIMEOUT_MS`), for the same reason: it is the time
/// after which silence is more likely a dead end than a slow answer. The
/// audit's fresh node fetched a mailbox in under two seconds.
pub const PRIME_TIMEOUT_MS: u32 = 30_000;

/// What became of a priming GET.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Primed {
    /// The node answered with state, so it holds the contract.
    Held,
    /// The node answered that nothing is stored under this id.
    Absent,
    /// No answer arrived before [`PRIME_TIMEOUT_MS`].
    TimedOut,
    /// The GET could not even be sent.
    NotAsked,
}

impl std::fmt::Display for Primed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Held => "it holds it",
            Self::Absent => "it answered not found",
            Self::TimedOut => "no answer in time",
            Self::NotAsked => "the GET could not be sent",
        })
    }
}

/// Updates waiting for the node to answer a GET for their contract.
///
/// Keyed by instance id because that is all a `GetResponse` or a `NotFound`
/// carries that identifies the contract.
#[derive(Default)]
pub struct PrimeWaiters {
    waiting: HashMap<ContractInstanceId, Vec<oneshot::Sender<Primed>>>,
}

impl PrimeWaiters {
    /// Wait for the next answer about `id`.
    ///
    /// Registered BEFORE the GET is sent, so an answer the node produces from
    /// its own store before `send` has even returned is not missed.
    pub fn register(&mut self, id: ContractInstanceId) -> oneshot::Receiver<Primed> {
        let (tx, rx) = oneshot::channel();
        // A waiter whose deadline fired, or whose GET could not be sent, has
        // dropped its receiver. Pruned across EVERY contract here, so one
        // that never answers and is never written to again does not keep an
        // entry for the life of the tab.
        self.waiting.retain(|_, waiting| {
            waiting.retain(|tx| !tx.is_canceled());
            !waiting.is_empty()
        });
        self.waiting.entry(id).or_default().push(tx);
        rx
    }

    /// Hand `outcome` to everything waiting on `id`. Returns how many were
    /// still listening.
    pub fn resolve(&mut self, id: &ContractInstanceId, outcome: Primed) -> usize {
        let Some(waiting) = self.waiting.remove(id) else {
            return 0;
        };
        waiting
            .into_iter()
            .filter_map(|tx| tx.send(outcome).ok())
            .count()
    }
}

// One registry per thread, which in the browser is the only thread. Under
// `cargo test` the threads are reused across tests, so a test using the real
// registry must resolve every waiter it registers, with ids no other test
// uses (see `response_handler`'s test).
thread_local! {
    static WAITERS: RefCell<PrimeWaiters> = RefCell::default();
}

/// Called by the response handler for every `GetResponse` (as
/// [`Primed::Held`]) and every `NotFound` (as [`Primed::Absent`]).
///
/// Waking a waiter only schedules it; it runs after the handler that called
/// this has finished, so by the time an update or a re-read resumes, the
/// state that came with the answer has already been applied to `APP_STATE`.
pub fn deliver_answer(id: &ContractInstanceId, outcome: Primed) {
    WAITERS.with(|waiters| waiters.borrow_mut().resolve(id, outcome));
}

/// Wait on the real registry, as the node-backed writer does. For the
/// response handler's tests, which must prove the handler feeds it.
#[cfg(test)]
pub(crate) fn register_answer_waiter(id: ContractInstanceId) -> oneshot::Receiver<Primed> {
    WAITERS.with(|waiters| waiters.borrow_mut().register(id))
}

/// The node, as far as priming needs to know it. A trait so the ORDERING --
/// the whole of the fix -- can be driven on the host with a fake whose GET
/// answers exactly when a test says so.
pub(crate) trait PrimeIo {
    fn register(&self, id: ContractInstanceId) -> oneshot::Receiver<Primed>;
    async fn get(&self, id: ContractInstanceId) -> Result<(), String>;
    async fn deadline(&self);
    async fn update(&self, key: ContractKey, data: UpdateData<'static>) -> Result<(), String>;
}

/// Ask the node for `id` and wait until it answers or the deadline passes.
pub(crate) async fn prime(io: &impl PrimeIo, id: ContractInstanceId) -> Primed {
    let answered = io.register(id);
    if let Err(e) = io.get(id).await {
        dioxus::logger::tracing::warn!("Could not ask the node for contract {id} first: {e}");
        return Primed::NotAsked;
    }
    let deadline = io.deadline();
    futures::pin_mut!(deadline);
    match futures::future::select(answered, deadline).await {
        futures::future::Either::Left((Ok(outcome), _)) => outcome,
        // The sender was dropped without answering. Nothing does that today;
        // it would mean the registry was replaced, which is silence.
        futures::future::Either::Left((Err(_), _)) => Primed::TimedOut,
        futures::future::Either::Right(((), _)) => Primed::TimedOut,
    }
}

/// Prime, then update. The update is sent whatever priming concluded; see the
/// module docs for why that is never worse than not priming.
pub(crate) async fn primed_update(
    io: &impl PrimeIo,
    key: ContractKey,
    data: UpdateData<'static>,
) -> Result<Primed, String> {
    let primed = prime(io, *key.id()).await;
    if primed != Primed::Held {
        dioxus::logger::tracing::warn!(
            "Updating contract {} without the node confirming it holds it ({primed})",
            key.id()
        );
    }
    io.update(key, data).await?;
    Ok(primed)
}

/// The real node.
#[cfg(target_arch = "wasm32")]
struct NodeIo;

#[cfg(target_arch = "wasm32")]
impl PrimeIo for NodeIo {
    fn register(&self, id: ContractInstanceId) -> oneshot::Receiver<Primed> {
        WAITERS.with(|waiters| waiters.borrow_mut().register(id))
    }
    async fn get(&self, id: ContractInstanceId) -> Result<(), String> {
        super::get_contract(&id, false).await
    }
    async fn deadline(&self) {
        gloo_timers::future::TimeoutFuture::new(PRIME_TIMEOUT_MS).await;
    }
    async fn update(&self, key: ContractKey, data: UpdateData<'static>) -> Result<(), String> {
        super::delegate_api::send_update(&key, data).await
    }
}

/// Send a contract update (delta or full state), once the node has answered
/// for the contract. The ONLY way the UI writes to a contract; see the module
/// docs.
///
/// Resolving `Ok` still means only that the update was handed to the node.
pub async fn update_contract(
    contract_key: &ContractKey,
    data: UpdateData<'static>,
) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        primed_update(&NodeIo, *contract_key, data)
            .await
            .map(|_| ())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (contract_key, data);
        Err("contract operations require WASM".into())
    }
}

/// Re-read a contract: GET it and wait for the node's answer, so that what is
/// in `APP_STATE` afterwards is the node's copy NOW rather than whatever
/// arrived last.
#[cfg(target_arch = "wasm32")]
pub async fn reread(id: ContractInstanceId) -> Primed {
    prime(&NodeIo, id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_stdlib::prelude::{CodeHash, StateDelta};
    use futures::executor::LocalPool;
    use futures::task::LocalSpawnExt;
    use std::rc::Rc;

    #[derive(Clone, Debug, PartialEq)]
    enum Event {
        Get,
        Update,
    }

    /// A node whose answers and deadline fire only when the test says.
    #[derive(Default)]
    struct FakeNode {
        waiters: RefCell<PrimeWaiters>,
        events: RefCell<Vec<Event>>,
        get_fails: bool,
        deadline: RefCell<Option<oneshot::Sender<()>>>,
    }

    impl PrimeIo for Rc<FakeNode> {
        fn register(&self, id: ContractInstanceId) -> oneshot::Receiver<Primed> {
            self.waiters.borrow_mut().register(id)
        }
        async fn get(&self, _id: ContractInstanceId) -> Result<(), String> {
            self.events.borrow_mut().push(Event::Get);
            if self.get_fails {
                Err("socket closed".into())
            } else {
                Ok(())
            }
        }
        async fn deadline(&self) {
            let (tx, rx) = oneshot::channel();
            *self.deadline.borrow_mut() = Some(tx);
            let _ = rx.await;
        }
        async fn update(
            &self,
            _key: ContractKey,
            _data: UpdateData<'static>,
        ) -> Result<(), String> {
            self.events.borrow_mut().push(Event::Update);
            Ok(())
        }
    }

    fn key() -> ContractKey {
        ContractKey::from_id_and_code(ContractInstanceId::new([3u8; 32]), CodeHash::new([4u8; 32]))
    }

    fn delta() -> UpdateData<'static> {
        UpdateData::Delta(StateDelta::from(vec![1u8, 2, 3]))
    }

    /// Where a spawned primed update leaves its result.
    type Outcome = Rc<RefCell<Option<Result<Primed, String>>>>;

    /// Start a primed update on `node` and run it as far as it will go.
    fn start(node: &Rc<FakeNode>) -> (LocalPool, Outcome) {
        let mut pool = LocalPool::new();
        let result = Rc::new(RefCell::new(None));
        let (io, out) = (node.clone(), result.clone());
        pool.spawner()
            .spawn_local(async move {
                *out.borrow_mut() = Some(primed_update(&io, key(), delta()).await);
            })
            .expect("spawn");
        pool.run_until_stalled();
        (pool, result)
    }

    /// **The fix itself.** The update is not sent while the GET is
    /// unanswered, and is sent as soon as the node answers.
    ///
    /// This is the ordering harvest#119 lost: with the old back-to-back
    /// sends, the update is already out when the pool first stalls.
    #[test]
    fn the_update_waits_for_the_node_to_answer_the_get() {
        let node = Rc::new(FakeNode::default());
        let (mut pool, result) = start(&node);

        assert_eq!(
            *node.events.borrow(),
            vec![Event::Get],
            "the update went out before the node said it holds the contract"
        );
        assert!(result.borrow().is_none());

        assert_eq!(
            node.waiters.borrow_mut().resolve(key().id(), Primed::Held),
            1
        );
        pool.run_until_stalled();

        assert_eq!(*node.events.borrow(), vec![Event::Get, Event::Update]);
        assert_eq!(*result.borrow(), Some(Ok(Primed::Held)));
    }

    /// An answer about a DIFFERENT contract releases nothing.
    #[test]
    fn an_answer_about_another_contract_does_not_release_the_update() {
        let node = Rc::new(FakeNode::default());
        let (mut pool, _result) = start(&node);

        let other = ContractInstanceId::new([9u8; 32]);
        assert_eq!(node.waiters.borrow_mut().resolve(&other, Primed::Held), 0);
        pool.run_until_stalled();
        assert_eq!(*node.events.borrow(), vec![Event::Get]);
    }

    /// Silence ends at the deadline, and the update is still sent: it is
    /// exactly what was sent before priming existed, so it cannot be worse.
    #[test]
    fn a_get_that_never_answers_still_lets_the_update_out_at_the_deadline() {
        let node = Rc::new(FakeNode::default());
        let (mut pool, result) = start(&node);
        assert_eq!(*node.events.borrow(), vec![Event::Get]);

        node.deadline
            .borrow_mut()
            .take()
            .expect("a deadline is armed once the GET is sent")
            .send(())
            .expect("fire");
        pool.run_until_stalled();

        assert_eq!(*node.events.borrow(), vec![Event::Get, Event::Update]);
        assert_eq!(*result.borrow(), Some(Ok(Primed::TimedOut)));
    }

    /// NotFound is an answer too, and releases the update.
    #[test]
    fn not_found_releases_the_update() {
        let node = Rc::new(FakeNode::default());
        let (mut pool, result) = start(&node);
        node.waiters
            .borrow_mut()
            .resolve(key().id(), Primed::Absent);
        pool.run_until_stalled();
        assert_eq!(*node.events.borrow(), vec![Event::Get, Event::Update]);
        assert_eq!(*result.borrow(), Some(Ok(Primed::Absent)));
    }

    /// A GET that could not be sent does not strand the update behind a
    /// deadline for an answer that cannot come.
    #[test]
    fn a_get_that_could_not_be_sent_does_not_wait_for_the_deadline() {
        let node = Rc::new(FakeNode {
            get_fails: true,
            ..FakeNode::default()
        });
        let (_pool, result) = start(&node);
        assert_eq!(*node.events.borrow(), vec![Event::Get, Event::Update]);
        assert_eq!(*result.borrow(), Some(Ok(Primed::NotAsked)));
    }

    /// Two writes to one contract are both released by one answer, and a
    /// waiter whose receiver is gone is pruned rather than kept forever.
    #[test]
    fn one_answer_releases_every_waiter_and_abandoned_ones_are_pruned() {
        let mut waiters = PrimeWaiters::default();
        let id = ContractInstanceId::new([1u8; 32]);
        let abandoned = waiters.register(id);
        drop(abandoned);
        let elsewhere = ContractInstanceId::new([2u8; 32]);
        drop(waiters.register(elsewhere));
        let _a = waiters.register(id);
        let _b = waiters.register(id);
        assert!(
            !waiters.waiting.contains_key(&elsewhere),
            "an abandoned waiter on another contract was kept"
        );
        assert_eq!(
            waiters.waiting[&id].len(),
            2,
            "the abandoned waiter was kept"
        );
        assert_eq!(waiters.resolve(&id, Primed::Held), 2);
        assert_eq!(waiters.resolve(&id, Primed::Held), 0, "answered twice");
    }
}
