//! API for communicating with delegates and contracts via the Freenet gateway.
//!
//! All functions require an active WebSocket connection (WEB_API must be Some).
//! These are only usable in WASM builds -- native stubs return errors.

#[cfg(target_arch = "wasm32")]
use dioxus::logger::tracing::info;
#[cfg(target_arch = "wasm32")]
use dioxus::prelude::*;
#[cfg(target_arch = "wasm32")]
use freenet_stdlib::client_api::{ClientRequest, ContractRequest, DelegateRequest};
use freenet_stdlib::prelude::*;

/// Send a request to a delegate (harvest or ghostkey).
pub async fn send_delegate_message(
    delegate_key: &DelegateKey,
    payload: Vec<u8>,
) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let request = ClientRequest::DelegateOp(DelegateRequest::ApplicationMessages {
            key: delegate_key.clone(),
            params: Parameters::from(harvest_common::delegate::DELEGATE_PARAMETERS),
            inbound: vec![InboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(payload),
            )],
        });

        let mut api = super::WEB_API.write();
        let web_api = api.as_mut().ok_or("not connected to gateway")?;
        web_api
            .send(request)
            .await
            .map_err(|e| format!("send delegate message: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (delegate_key, payload);
        Err("delegate messaging requires WASM".into())
    }
}

/// Arm the Harvest delegate to answer instant-checkout requests for one store
/// (`crate::auto_invoice_flow`).
pub async fn arm_auto_invoice(arm: harvest_common::delegate::AutoInvoiceArm) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let delegate_key = super::APP_STATE
            .read()
            .harvest_delegate_key
            .clone()
            .ok_or("harvest delegate not yet registered")?;
        let payload =
            harvest_common::to_cbor(&harvest_common::HarvestDelegateRequest::ArmAutoInvoice {
                arm: Box::new(arm),
            })
            .map_err(|e| format!("serialize ArmAutoInvoice: {e}"))?;
        send_delegate_message(&delegate_key, payload).await
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = arm;
        Err("delegate messaging requires WASM".into())
    }
}

/// GET a contract's state, optionally subscribing to updates.
pub async fn get_contract(
    contract_key: &ContractInstanceId,
    subscribe: bool,
) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        info!("GET contract (subscribe={subscribe}): {:?}", contract_key);

        let request = ClientRequest::ContractOp(ContractRequest::Get {
            key: *contract_key,
            return_contract_code: false,
            subscribe,
            blocking_subscribe: false,
        });

        let mut api = super::WEB_API.write();
        let web_api = api.as_mut().ok_or("not connected to gateway")?;
        web_api
            .send(request)
            .await
            .map_err(|e| format!("get contract: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (contract_key, subscribe);
        Err("contract operations require WASM".into())
    }
}

/// GET-and-subscribe a contract by its raw 32-byte instance id.
///
/// Contract ids reach the UI as `Vec<u8>` -- from delegate registrations and
/// from other contracts' state -- so this is the one place that checks the
/// length before turning them into a `ContractInstanceId`.
pub async fn get_contract_by_id(contract_id: &[u8]) -> Result<(), String> {
    let id_bytes: [u8; 32] = contract_id
        .try_into()
        .map_err(|_| "contract id must be 32 bytes".to_string())?;
    get_contract(&ContractInstanceId::new(id_bytes), true).await
}

/// Put a contract update on the wire, with nothing in front of it.
///
/// Not for direct use: a node that does not yet hold the contract bounces
/// this with a retry request nothing can correlate (harvest#119). Every
/// caller goes through [`super::update_contract`], which waits for the node
/// to answer a GET for the contract first.
pub(super) async fn send_update(
    contract_key: &ContractKey,
    data: UpdateData<'static>,
) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let request = ClientRequest::ContractOp(ContractRequest::Update {
            key: *contract_key,
            data,
        });

        let mut api = super::WEB_API.write();
        let web_api = api.as_mut().ok_or("not connected to gateway")?;
        web_api
            .send(request)
            .await
            .map_err(|e| format!("update contract: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (contract_key, data);
        Err("contract operations require WASM".into())
    }
}

/// PUT a new contract onto the network and subscribe to it.
pub async fn put_contract(contract: ContractContainer, state: WrappedState) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        let request = ClientRequest::ContractOp(ContractRequest::Put {
            contract,
            state,
            related_contracts: RelatedContracts::new(),
            subscribe: true,
            blocking_subscribe: false,
        });

        let mut api = super::WEB_API.write();
        let web_api = api.as_mut().ok_or("not connected to gateway")?;
        web_api
            .send(request)
            .await
            .map_err(|e| format!("put contract: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (contract, state);
        Err("contract operations require WASM".into())
    }
}

/// Delegate registrations the node has not answered yet (harvest#162,
/// harvest#163).
///
/// The node answers `RegisterDelegate` with an empty `DelegateResponse` only
/// once the delegate is stored and its module compiled, and it runs each
/// client request as its own task, so a message sent to the delegate before
/// that answer can overtake the registration and be refused as
/// `DelegateError::Missing`. That error carries no request id, so nothing
/// retries the message: on the first load after a delegate re-key, the
/// migration walk stopped ("current delegate unavailable") and a request the
/// page waits on (the payment key) never got an answer. So what is sent to a
/// delegate waits for this answer; see [`registered`].
#[derive(Default)]
pub struct RegistrationWaiters {
    waiting: std::collections::HashMap<DelegateKey, futures::channel::oneshot::Sender<()>>,
    receivers: std::collections::HashMap<DelegateKey, futures::channel::oneshot::Receiver<()>>,
}

impl RegistrationWaiters {
    /// A registration of `key` is about to be sent.
    pub fn expect(&mut self, key: DelegateKey) {
        let (tx, rx) = futures::channel::oneshot::channel();
        self.waiting.insert(key.clone(), tx);
        self.receivers.insert(key, rx);
    }

    /// An empty answer from `key` arrived. `true` if it was the answer to a
    /// registration of it, which nothing else may then act on; any later empty
    /// answer is left to its usual reader (the migration walk's "not
    /// registered", `delegate_migrate_ops::offer_empty`).
    pub fn acknowledge(&mut self, key: &DelegateKey) -> bool {
        match self.waiting.remove(key) {
            Some(tx) => {
                let _ = tx.send(());
                true
            }
            None => false,
        }
    }

    /// The answer to `key`'s registration is no longer expected.
    pub fn forget(&mut self, key: &DelegateKey) {
        self.waiting.remove(key);
        self.receivers.remove(key);
    }

    /// What to wait on for `key`'s registration, once.
    pub fn take(&mut self, key: &DelegateKey) -> Option<futures::channel::oneshot::Receiver<()>> {
        self.receivers.remove(key)
    }
}

thread_local! {
    static REGISTRATIONS: std::cell::RefCell<RegistrationWaiters> =
        std::cell::RefCell::default();
}

/// Called by the response handler for every empty delegate answer: see
/// [`RegistrationWaiters::acknowledge`].
pub fn acknowledge_registration(key: &DelegateKey) -> bool {
    REGISTRATIONS.with(|r| r.borrow_mut().acknowledge(key))
}

/// How long [`registered`] waits for the node's answer before going ahead
/// anyway, as it did before this wait existed.
pub const REGISTRATION_WAIT_MS: u32 = 30_000;
// Well above the slowest answer measured (7.1 s in the harvest#162
// rehearsal): a wait that gives up first is no wait at all.
const _: () = assert!(REGISTRATION_WAIT_MS >= 15_000);

/// A wait for the node's answer to the registration of `key`, with its
/// [`REGISTRATION_WAIT_MS`] deadline running from NOW, so the waits for two
/// delegates run side by side even when one is awaited after the other.
/// Resolves `false` on the timeout, and then stops expecting the answer, so a
/// registration the node refused does not leave a later empty answer from
/// that key taken for it. Needs the response loop running, so it is awaited
/// from a spawned task, never before the loop.
#[cfg(target_arch = "wasm32")]
pub fn registered(key: &DelegateKey) -> impl std::future::Future<Output = bool> {
    let rx = REGISTRATIONS.with(|r| r.borrow_mut().take(key));
    let deadline = gloo_timers::future::TimeoutFuture::new(REGISTRATION_WAIT_MS);
    let key = key.clone();
    async move {
        let answered = wait_for_answer(rx, deadline).await;
        if !answered {
            REGISTRATIONS.with(|r| r.borrow_mut().forget(&key));
        }
        answered
    }
}

/// `true` once `answer` arrives, `false` if `deadline` comes first. A
/// registration nothing recorded (`None`) has nothing to wait for.
pub async fn wait_for_answer(
    answer: Option<futures::channel::oneshot::Receiver<()>>,
    deadline: impl std::future::Future<Output = ()>,
) -> bool {
    let Some(answer) = answer else {
        return true;
    };
    futures::pin_mut!(deadline);
    matches!(
        futures::future::select(answer, deadline).await,
        futures::future::Either::Left((Ok(()), _))
    )
}

/// Register a delegate with the Freenet node. What is sent to it afterwards
/// waits for [`registered`].
pub async fn register_delegate(delegate_wasm: &[u8]) -> Result<DelegateKey, String> {
    #[cfg(target_arch = "wasm32")]
    {
        let delegate_code = DelegateCode::from(delegate_wasm.to_vec());
        // Half of the delegate's address, so it is named once
        // (`harvest_common::delegate::DELEGATE_PARAMETERS`) rather than spelled
        // out here and again at every other registration site. The address
        // guard reads the same constant, so a change to it shows up as a moved
        // delegate key instead of as nothing at all.
        let params = Parameters::from(harvest_common::delegate::DELEGATE_PARAMETERS);
        let delegate = Delegate::from((&delegate_code, &params));
        let container = DelegateContainer::Wasm(DelegateWasmAPIVersion::V1(delegate));
        let key = container.key().clone();

        // `DelegateRequest::DEFAULT_CIPHER` / `DEFAULT_NONCE` existed in
        // freenet-stdlib 0.6 and are gone in 0.8. Zeroes are the correct
        // replacement rather than a placeholder: since freenet-core#4140 the
        // node IGNORES the client-supplied cipher and nonce entirely and
        // derives a per-delegate key from its own KEK, so these bytes never
        // reach any cryptographic operation. ghostkeys does the same thing for
        // the same reason (`ui/src/api/delegate.rs`).
        let request = ClientRequest::DelegateOp(DelegateRequest::RegisterDelegate {
            delegate: container,
            cipher: [0u8; 32],
            nonce: [0u8; 24],
        });
        // Before the send: the answer can arrive as soon as it returns.
        REGISTRATIONS.with(|r| r.borrow_mut().expect(key.clone()));

        let mut api = super::WEB_API.write();
        let web_api = api.as_mut().ok_or("not connected to gateway")?;
        web_api
            .send(request)
            .await
            .map_err(|e| format!("register delegate: {e}"))?;

        info!("Registered delegate: {:?}", key);
        Ok(key)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = delegate_wasm;
        Err("delegate registration requires WASM".into())
    }
}

#[cfg(test)]
mod registration_tests {
    use super::*;

    fn key(byte: u8) -> DelegateKey {
        DelegateKey::new([byte; 32], CodeHash::new([byte; 32]))
    }

    /// The first empty answer from a delegate being registered is the
    /// registration's, and releases whatever waits on it; one from any other
    /// delegate, or a second one, is left to its usual reader (harvest#162).
    #[test]
    fn the_first_empty_answer_acknowledges_the_registration() {
        let mut waiters = RegistrationWaiters::default();
        waiters.expect(key(1));
        let mut rx = waiters.take(&key(1)).expect("something to wait on");
        assert!(!waiters.acknowledge(&key(2)));
        assert_eq!(rx.try_recv(), Ok(None), "not yet");
        assert!(waiters.acknowledge(&key(1)));
        assert_eq!(rx.try_recv(), Ok(Some(())));
        assert!(
            !waiters.acknowledge(&key(1)),
            "a later one is not the registration's"
        );
        assert!(waiters.take(&key(1)).is_none(), "waited on once");
    }

    /// The wait returns when the answer comes, and gives up at the deadline.
    #[test]
    fn a_registration_wait_ends_with_its_answer_or_its_deadline() {
        use futures::executor::block_on;
        let mut waiters = RegistrationWaiters::default();
        waiters.expect(key(1));
        let rx = waiters.take(&key(1));
        assert!(waiters.acknowledge(&key(1)));
        assert!(block_on(wait_for_answer(rx, futures::future::pending())));

        waiters.expect(key(2));
        let rx = waiters.take(&key(2));
        assert!(!block_on(wait_for_answer(rx, futures::future::ready(()))));
        // Given up on: a later empty answer is not taken for it.
        waiters.forget(&key(2));
        assert!(!waiters.acknowledge(&key(2)));
    }

    /// Nothing is sent to either delegate, and neither key is published to
    /// the rest of the app, before the node has answered its registration;
    /// Harvest's first, since the ghostkey's answers start Harvest work; the
    /// migration walk after both (harvest#162, harvest#163). The waiter is
    /// recorded before the registration is sent. Pinned by source: the
    /// connect flow is wasm-only.
    #[test]
    fn the_app_waits_for_each_registration_before_using_the_delegate() {
        let src = include_str!("../components/app.rs");
        let task = &src[src.find("let ghostkey_key = match").unwrap()..];
        let task = &task[task
            .find("wasm_bindgen_futures::spawn_local(async move {")
            .expect("spawned")..];
        // The task alone, to its closing brace.
        let task = &task[..task
            .find("\n                });\n")
            .expect("the task's end")];
        let order = [
            "let harvest_wait = harvest_key",
            "let ghostkey_wait = ghostkey_key",
            "harvest_wait.await",
            "harvest_delegate_key = Some(key)",
            "harvest_delegate_ready().await",
            "ghostkey_wait.await",
            "ghostkey_delegate_key =",
            "ghostkey_delegate_ready(key).await",
            "crate::gateway::delegate_migrate_ops::start();",
        ];
        let mut at = 0;
        for step in order {
            at += task[at..]
                .find(step)
                .unwrap_or_else(|| panic!("{step}, in order, inside the task"))
                + step.len();
        }
        // Both deadlines start together, before either is awaited.
        assert_eq!(task.matches("delegate_registered(").count(), 2);
        // Set nowhere else, and the walk started nowhere else.
        assert_eq!(src.matches("harvest_delegate_key =").count(), 1);
        assert_eq!(src.matches("ghostkey_delegate_key =").count(), 1);
        assert_eq!(src.matches("delegate_migrate_ops::start()").count(), 1);

        let this = include_str!("delegate_api.rs");
        let register = &this[this.find("pub async fn register_delegate(").unwrap()..];
        let expect = register
            .find("r.borrow_mut().expect(key.clone())")
            .expect("recorded");
        let send = register.find(".send(request)").expect("sent");
        assert!(expect < send, "recorded before it is sent");
        let wait = &this[this.find("pub fn registered(").unwrap()..];
        let wait = &wait[..wait.find("\n}\n").unwrap()];
        for part in [
            "r.borrow_mut().take(key)",
            "TimeoutFuture::new(REGISTRATION_WAIT_MS)",
            "wait_for_answer(rx, deadline).await",
        ] {
            assert!(wait.contains(part), "registered() {part}");
        }

        // And the answer reaches the waiters, before the walk's reader of
        // empty answers can take it.
        let handler = include_str!("response_handler.rs");
        let handler = &handler[handler.find("fn handle_delegate_response(").unwrap()..];
        let ack = handler
            .find("values.is_empty() && super::delegate_api::acknowledge_registration(&key)")
            .expect("acknowledged");
        let empty = handler.find("offer_empty(&key)").expect("walk's reader");
        assert!(ack < empty);

        // And the payment key's answer is not waited on forever (harvest#163).
        let ready = &src[src.find("async fn harvest_delegate_ready()").unwrap()..];
        let ready = &ready[..ready.find("\n}\n").unwrap()];
        let asked = ready.find("get_payment_xpub()").expect("asked");
        let timer = ready
            .find("TimeoutFuture::new(crate::state::PAYMENT_KEY_ANSWER_WAIT_MS)")
            .expect("a deadline");
        let overdue = ready
            .find("payment_key_answer_overdue()")
            .expect("then shown");
        assert!(asked < timer && timer < overdue);
    }
}
