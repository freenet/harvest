//! Listing photos on the network: one image contract per photo, addressed by
//! the BLAKE3 hash of its bytes (`harvest_image`, harvest#212).
//!
//! The seller's upload PUTs each photo and waits for the node to acknowledge
//! it before the listing naming it is signed; the seller's listings page GETs
//! them to find any that have gone missing. Both wait on the shared response
//! handler, which hands every answer about an image contract here and NOT to
//! `on_contract_state`: an image is not store, mailbox or reputation state,
//! and must never be decoded as one.
//!
//! The waiting itself ([`ImageWaiters`]) is pure and tested on the host; only
//! the sends need a browser.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractWasmAPIVersion, Parameters,
    WrappedContract,
};
use futures::channel::oneshot;

/// The image contract, exactly as built (`scripts/build-contract-wasm.sh`).
pub const IMAGE_CONTRACT_WASM: &[u8] = include_bytes!("../../public/contracts/image_contract.wasm");

/// The image contract instance for a photo whose bytes hash to `hash`.
pub fn image_contract(hash: [u8; 32]) -> (ContractContainer, ContractInstanceId) {
    let code = Arc::new(ContractCode::from(IMAGE_CONTRACT_WASM.to_vec()));
    let wrapped = WrappedContract::new(code, Parameters::from(hash.to_vec()));
    let id = *wrapped.key().id();
    (
        ContractContainer::Wasm(ContractWasmAPIVersion::V1(wrapped)),
        id,
    )
}

/// The instance id alone.
pub fn image_instance_id(hash: [u8; 32]) -> ContractInstanceId {
    image_contract(hash).1
}

/// What the node said about a photo it was asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetched {
    /// Its bytes. Not yet checked against anything: the caller does that.
    Bytes(Vec<u8>),
    /// The node answered that nothing is stored under this id.
    Absent,
    /// No answer before the deadline.
    TimedOut,
}

/// Who is waiting on which image contract, and which ids are images at all.
///
/// An id is registered as an image the first time it is PUT or fetched, and
/// stays registered for the life of the tab, so a later answer for it (an
/// update notification from a subscription, a slow `GetResponse`) is still
/// recognised as an image and kept away from the store state.
#[derive(Default)]
pub struct ImageWaiters {
    images: HashSet<ContractInstanceId>,
    puts: HashMap<ContractInstanceId, Vec<oneshot::Sender<()>>>,
    gets: HashMap<ContractInstanceId, Vec<oneshot::Sender<Fetched>>>,
}

impl ImageWaiters {
    /// Wait for the node to acknowledge a PUT of `id`. Registered BEFORE the
    /// PUT is sent, so an acknowledgement that beats `send` is not missed.
    pub fn register_put(&mut self, id: ContractInstanceId) -> oneshot::Receiver<()> {
        self.prune();
        self.images.insert(id);
        let (tx, rx) = oneshot::channel();
        self.puts.entry(id).or_default().push(tx);
        rx
    }

    /// Wait for the node's answer to a GET of `id`.
    pub fn register_get(&mut self, id: ContractInstanceId) -> oneshot::Receiver<Fetched> {
        self.prune();
        self.images.insert(id);
        let (tx, rx) = oneshot::channel();
        self.gets.entry(id).or_default().push(tx);
        rx
    }

    /// Whether `id` is an image contract this tab has dealt with.
    pub fn is_image(&self, id: &ContractInstanceId) -> bool {
        self.images.contains(id)
    }

    /// A `PutResponse` for `id`. Returns whether `id` is an image.
    pub fn put_acknowledged(&mut self, id: &ContractInstanceId) -> bool {
        if let Some(waiting) = self.puts.remove(id) {
            for tx in waiting {
                let _ = tx.send(());
            }
        }
        self.images.contains(id)
    }

    /// A `GetResponse` (or an update notification) carrying `bytes` for
    /// `id`. A state for an image just PUT also proves the node holds it, so
    /// it settles a waiting PUT too. Returns whether `id` is an image.
    pub fn state(&mut self, id: &ContractInstanceId, bytes: &[u8]) -> bool {
        if let Some(waiting) = self.gets.remove(id) {
            for tx in waiting {
                let _ = tx.send(Fetched::Bytes(bytes.to_vec()));
            }
        }
        if !bytes.is_empty() {
            if let Some(waiting) = self.puts.remove(id) {
                for tx in waiting {
                    let _ = tx.send(());
                }
            }
        }
        self.images.contains(id)
    }

    /// A `NotFound` for `id`. Returns whether `id` is an image.
    pub fn absent(&mut self, id: &ContractInstanceId) -> bool {
        if let Some(waiting) = self.gets.remove(id) {
            for tx in waiting {
                let _ = tx.send(Fetched::Absent);
            }
        }
        self.images.contains(id)
    }

    /// Drop waiters whose caller gave up (its deadline fired).
    fn prune(&mut self) {
        self.puts.retain(|_, w| {
            w.retain(|tx| !tx.is_canceled());
            !w.is_empty()
        });
        self.gets.retain(|_, w| {
            w.retain(|tx| !tx.is_canceled());
            !w.is_empty()
        });
    }
}

thread_local! {
    static WAITERS: RefCell<ImageWaiters> = RefCell::default();
}

/// Called by the response handler for every `GetResponse` and update
/// notification. True if `id` is an image, which the caller must then NOT
/// pass on as store, mailbox or reputation state.
pub fn deliver_state(id: &ContractInstanceId, bytes: &[u8]) -> bool {
    WAITERS.with(|w| w.borrow_mut().state(id, bytes))
}

/// Whether `id` is an image contract this tab has PUT or fetched.
pub fn is_image(id: &ContractInstanceId) -> bool {
    WAITERS.with(|w| w.borrow().is_image(id))
}

/// Called by the response handler for every `PutResponse`.
pub fn deliver_put_ack(id: &ContractInstanceId) -> bool {
    WAITERS.with(|w| w.borrow_mut().put_acknowledged(id))
}

/// Called by the response handler for every `NotFound`.
pub fn deliver_absent(id: &ContractInstanceId) -> bool {
    WAITERS.with(|w| w.borrow_mut().absent(id))
}

/// How long a photo's PUT is waited on before the upload is told it failed.
/// A PUT is answered once the node has stored it, which on the seller's own
/// node is quick; the rest of the network's copies follow in the background.
pub const PUT_TIMEOUT_MS: u32 = 30_000;

/// How long a GET is waited on.
pub const GET_TIMEOUT_MS: u32 = 30_000;

/// PUT a photo (its exact bytes, already checked with
/// `harvest_image::validate`) and subscribe to it, then wait until the node
/// acknowledges it. The subscription is the seller's local claim on the
/// photo while this tab is open (images design, section 3.5).
pub async fn put_image(hash: [u8; 32], bytes: Vec<u8>) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        use freenet_stdlib::prelude::WrappedState;
        let (container, id) = image_contract(hash);
        let acknowledged = WAITERS.with(|w| w.borrow_mut().register_put(id));
        super::put_contract(container, WrappedState::new(bytes)).await?;
        let deadline = gloo_timers::future::TimeoutFuture::new(PUT_TIMEOUT_MS);
        futures::pin_mut!(deadline);
        match futures::future::select(acknowledged, deadline).await {
            futures::future::Either::Left((Ok(()), _)) => Ok(()),
            futures::future::Either::Left((Err(_), _)) => Err("the upload was cancelled".into()),
            futures::future::Either::Right(_) => Err(format!(
                "Freenet did not confirm the photo within {} seconds",
                PUT_TIMEOUT_MS / 1000
            )),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (hash, bytes);
        Err("contract operations require WASM".into())
    }
}

/// GET a photo, optionally subscribing to it, and wait for the node's answer.
pub async fn fetch_image(hash: [u8; 32], subscribe: bool) -> Fetched {
    #[cfg(target_arch = "wasm32")]
    {
        let id = image_instance_id(hash);
        let answer = WAITERS.with(|w| w.borrow_mut().register_get(id));
        if super::get_contract(&id, subscribe).await.is_err() {
            return Fetched::TimedOut;
        }
        let deadline = gloo_timers::future::TimeoutFuture::new(GET_TIMEOUT_MS);
        futures::pin_mut!(deadline);
        match futures::future::select(answer, deadline).await {
            futures::future::Either::Left((Ok(fetched), _)) => fetched,
            _ => Fetched::TimedOut,
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (hash, subscribe);
        Fetched::TimedOut
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> ContractInstanceId {
        image_instance_id([n; 32])
    }

    #[test]
    fn the_instance_id_is_the_image_contracts_key_for_that_hash() {
        // The same derivation a node makes: BLAKE3(BLAKE3(wasm) || hash).
        let code_hash = blake3::hash(IMAGE_CONTRACT_WASM);
        let mut h = blake3::Hasher::new();
        h.update(code_hash.as_bytes());
        h.update(&[5u8; 32]);
        assert_eq!(id(5).as_bytes(), h.finalize().as_bytes());
        assert_ne!(id(5), id(6));
    }

    #[test]
    fn a_put_is_settled_by_its_acknowledgement() {
        let mut w = ImageWaiters::default();
        let mut rx = w.register_put(id(1));
        assert_eq!(rx.try_recv(), Ok(None));
        assert!(w.put_acknowledged(&id(1)));
        assert_eq!(rx.try_recv(), Ok(Some(())));
    }

    #[test]
    fn a_put_is_settled_by_the_state_coming_back() {
        let mut w = ImageWaiters::default();
        let mut rx = w.register_put(id(1));
        assert!(w.state(&id(1), b"jpeg"));
        assert_eq!(rx.try_recv(), Ok(Some(())));
    }

    #[test]
    fn an_empty_state_does_not_settle_a_put() {
        let mut w = ImageWaiters::default();
        let mut rx = w.register_put(id(1));
        w.state(&id(1), b"");
        assert_eq!(rx.try_recv(), Ok(None));
    }

    #[test]
    fn a_get_is_answered_with_bytes_or_absence() {
        let mut w = ImageWaiters::default();
        let mut found = w.register_get(id(1));
        let mut missing = w.register_get(id(2));
        assert!(w.state(&id(1), b"jpeg"));
        assert!(w.absent(&id(2)));
        assert_eq!(found.try_recv(), Ok(Some(Fetched::Bytes(b"jpeg".to_vec()))));
        assert_eq!(missing.try_recv(), Ok(Some(Fetched::Absent)));
    }

    #[test]
    fn an_answer_about_another_id_settles_nothing() {
        let mut w = ImageWaiters::default();
        let mut rx = w.register_get(id(1));
        assert!(!w.state(&id(9), b"jpeg"));
        assert!(!w.absent(&id(9)));
        assert!(!w.put_acknowledged(&id(9)));
        assert_eq!(rx.try_recv(), Ok(None));
    }

    /// The point of `is_image`: an answer that arrives AFTER its waiter is
    /// gone (a subscription's notification, a slow GET) is still recognised,
    /// so the response handler keeps it away from the store state.
    #[test]
    fn an_id_stays_an_image_after_its_waiters_are_gone() {
        let mut w = ImageWaiters::default();
        drop(w.register_get(id(1)));
        assert!(w.state(&id(1), b"jpeg"));
        assert!(w.is_image(&id(1)));
        assert!(!w.is_image(&id(2)));
    }

    #[test]
    fn a_waiter_whose_caller_gave_up_is_pruned() {
        let mut w = ImageWaiters::default();
        drop(w.register_put(id(1)));
        let _kept = w.register_get(id(2));
        assert!(w.puts.is_empty(), "the abandoned put waiter is dropped");
    }
}
