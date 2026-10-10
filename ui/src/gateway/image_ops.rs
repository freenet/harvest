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

/// The image contract's superseded generations (`legacy/image_contract.toml`).
/// Empty: nothing here looks a photo up under an older generation yet, and
/// nothing copies a seller's photos forward. A test fails the moment a row
/// is recorded, so whoever re-keys the image contract builds that first
/// (images design, section 3.2, "When it does move").
#[allow(dead_code)]
mod image_gen {
    include!(concat!(env!("OUT_DIR"), "/legacy_image_contract.rs"));
}

/// The image contract instance for a photo whose bytes hash to `hash`.
pub fn image_contract(hash: [u8; 32]) -> (ContractContainer, ContractInstanceId) {
    // Built (copied and hashed) once: the listings page asks for every
    // photo of every listing, and the WASM is about 170 KiB.
    static CODE: std::sync::OnceLock<Arc<ContractCode<'static>>> = std::sync::OnceLock::new();
    let code = CODE
        .get_or_init(|| Arc::new(ContractCode::from(IMAGE_CONTRACT_WASM.to_vec())))
        .clone();
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
    /// The node answered that nothing is stored under this id. ONE such
    /// answer is not proof: a GET that dead-ends can answer NotFound for a
    /// contract that exists. Ask again before concluding a photo is gone.
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

    /// A `GetResponse` carrying `bytes` for `id`. A state for an image just
    /// PUT also proves the node holds it, so it settles a waiting PUT too.
    /// Returns whether `id` is an image.
    ///
    /// Update notifications for an image are dropped by the handler before
    /// reaching here: a photo's state never changes, so one carries nothing
    /// a waiter needs.
    pub fn state(&mut self, id: &ContractInstanceId, bytes: &[u8]) -> bool {
        if let Some(waiting) = self.gets.remove(id) {
            // An empty state is no image (the contract refuses one), so it
            // answers as absence, never as a photo that is there.
            let answer = if bytes.is_empty() {
                Fetched::Absent
            } else {
                Fetched::Bytes(bytes.to_vec())
            };
            for tx in waiting {
                let _ = tx.send(answer.clone());
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

/// Called by the response handler for every `GetResponse`. True if `id` is
/// an image, which the caller must then NOT
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

/// How long a photo's PUT is waited on. A `PutResponse` may come only once
/// the PUT has travelled its route, which on a poorly connected peer is slow;
/// a PUT with no answer by then is checked by a GET (see [`put_image`]).
pub const PUT_TIMEOUT_MS: u32 = 60_000;

/// How long a GET is waited on.
pub const GET_TIMEOUT_MS: u32 = 30_000;

/// The seller-facing message for any upload that did not go through. The
/// detail goes to the log; the seller can only try again.
pub const UPLOAD_FAILED: &str =
    "A photo could not be uploaded to Freenet. Check that Freenet is running, then try again.";

/// PUT a photo and subscribe to it, then wait until the node has it. The
/// subscription is the seller's local claim on the photo while this tab is
/// open (images design, section 3.5).
///
/// The (hash, bytes) pair is checked first with the image contract's own
/// rules, so a mismatch is refused here with a reason rather than by the
/// node with silence. "The node has it" is a `PutResponse`, or a non-empty
/// state for the photo from any GET; with neither by the deadline, one GET
/// settles it, since an identical re-PUT of a photo the node already holds
/// may not be answered at all.
pub async fn put_image(hash: [u8; 32], bytes: Vec<u8>) -> Result<(), String> {
    if let Err(e) = harvest_image::validate(&hash, &bytes) {
        dioxus::logger::tracing::error!("refusing to upload an invalid photo: {e}");
        return Err(UPLOAD_FAILED.into());
    }
    #[cfg(target_arch = "wasm32")]
    {
        use freenet_stdlib::prelude::WrappedState;
        let (container, id) = image_contract(hash);
        let acknowledged = WAITERS.with(|w| w.borrow_mut().register_put(id));
        if let Err(e) = super::put_contract(container, WrappedState::new(bytes)).await {
            dioxus::logger::tracing::warn!("photo PUT could not be sent: {e}");
            return Err(UPLOAD_FAILED.into());
        }
        let deadline = gloo_timers::future::TimeoutFuture::new(PUT_TIMEOUT_MS);
        futures::pin_mut!(deadline);
        if let futures::future::Either::Left((Ok(()), _)) =
            futures::future::select(acknowledged, deadline).await
        {
            return Ok(());
        }
        // Asked twice before "not found" counts: one absence can be a dead-end
        // GET, or a stale answer to an earlier GET of the same photo (the
        // listings page checks photos too) that settled this one.
        let answer = match fetch_image(hash, false).await {
            Fetched::Absent => fetch_image(hash, false).await,
            other => other,
        };
        match answer {
            Fetched::Bytes(held) if harvest_image::validate(&hash, &held).is_ok() => Ok(()),
            other => {
                let said = match other {
                    Fetched::Bytes(_) => "bytes that are not this photo",
                    Fetched::Absent => "not found",
                    Fetched::TimedOut => "no answer",
                };
                dioxus::logger::tracing::warn!("photo PUT unconfirmed; a GET found {said}");
                Err(UPLOAD_FAILED.into())
            }
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

    /// See `image_gen`: re-keying the image contract strands every photo
    /// until something looks them up under the old generation and copies
    /// them forward, and nothing does yet.
    #[test]
    fn no_image_generation_is_recorded_until_photos_can_be_carried_forward() {
        assert!(
            image_gen::LEGACY_IMAGE_CONTRACT.is_empty(),
            "an image contract generation was recorded: build the buyer's \
             legacy lookup and the seller's copy-forward first"
        );
    }

    /// The response handler offers an answer to the image waiters BEFORE the
    /// migration probe and the store-state handler, so a photo's bytes are
    /// never decoded as store state. A source pin: the ordering lives in a
    /// browser-only match arm no host test can drive.
    #[test]
    fn the_handler_offers_answers_to_photos_first() {
        // Comment lines dropped, so a call commented out does not count.
        let src: String = include_str!("response_handler.rs")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let get_arm = &src[src.find("ContractResponse::GetResponse {").unwrap()..];
        let photo = get_arm
            .find("image_ops::deliver_state")
            .expect("photos are offered the state");
        let probe = get_arm.find("migrate_ops::deliver_state").unwrap();
        let store = get_arm.find("on_contract_state(").unwrap();
        assert!(photo < probe && photo < store, "photos must be asked first");
        let not_found = &src[src
            .find("ContractResponse::NotFound { instance_id }")
            .unwrap()..];
        let photo = not_found
            .find("image_ops::deliver_absent")
            .expect("photos hear absence");
        let probe = not_found.find("migrate_ops::deliver_absent").unwrap();
        assert!(photo < probe);
        assert!(
            src.contains("image_ops::deliver_put_ack"),
            "photos hear their PUT acknowledged"
        );
        // An update notification for a photo stops before the re-GET that
        // every other contract's notification triggers.
        let update = &src[src.find("ContractResponse::UpdateNotification {").unwrap()..];
        let photo = update
            .find("image_ops::is_image")
            .expect("photo notifications are recognised");
        let ret = update[photo..].find("return;").unwrap() + photo;
        let regets = update
            .find("get_contract")
            .expect("other notifications are re-read");
        assert!(ret < regets, "and dropped before anything is re-read");
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
    fn an_empty_state_answers_a_get_as_absent() {
        let mut w = ImageWaiters::default();
        let mut rx = w.register_get(id(1));
        w.state(&id(1), b"");
        assert_eq!(rx.try_recv(), Ok(Some(Fetched::Absent)));
    }

    #[test]
    fn an_invalid_pair_is_refused_before_anything_is_sent() {
        let jpeg = include_bytes!("../../../harvest-image/tests/fixtures/chromium-canvas.jpg");
        let wrong_hash = [7u8; 32];
        let refused = futures::executor::block_on(put_image(wrong_hash, jpeg.to_vec()));
        // Off wasm, a pair that passed would reach the native stub and fail
        // with ITS message, so equality with UPLOAD_FAILED is what shows the
        // refusal came from validation. Keep the stub's message different.
        assert_eq!(refused, Err(UPLOAD_FAILED.to_string()));
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
        // A late answer for it is still claimed (true), so the handler does
        // not pass a photo on as store or mailbox state.
        assert!(w.state(&id(1), b"jpeg"));
        assert!(w.absent(&id(1)));
        assert!(w.is_image(&id(1)));
        assert!(!w.is_image(&id(2)));
        assert!(
            !w.state(&id(2), b"jpeg"),
            "an id never asked about is not claimed"
        );
    }

    #[test]
    fn a_waiter_whose_caller_gave_up_is_pruned() {
        let mut w = ImageWaiters::default();
        drop(w.register_put(id(1)));
        let _kept = w.register_get(id(2));
        assert!(w.puts.is_empty(), "the abandoned put waiter is dropped");
    }
}
